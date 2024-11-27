/* unit tests */
use crate::{sale::Sale, SaleCondition};
#[cfg(test)]
use crate::Contract;
use near_sdk::{
    collections::UnorderedSet, env, json_types::U128, test_utils::{accounts, VMContextBuilder}, testing_env, AccountId, NearToken
};

const MIN_REQUIRED_APPROVAL_YOCTO: NearToken = NearToken::from_yoctonear(170000000000000000000);
const MIN_REQUIRED_STORAGE_YOCTO: NearToken =  NearToken::from_millinear(100);

const ONE_YOCTONEAR: NearToken = NearToken::from_yoctonear(1);

fn get_context(predecessor: AccountId) -> VMContextBuilder {
    let mut builder = VMContextBuilder::new();
    builder.predecessor_account_id(predecessor);
    builder
}

#[test]
#[should_panic(expected = "The contract is not initialized")]
fn test_default() {
    let context = get_context(accounts(0));
    testing_env!(context.build());
    let _contract = Contract::default();
}

#[test]
#[should_panic(expected = "Requires minimum deposit of 0.010 NEAR")]
fn test_storage_deposit_insufficient_deposit() {
    let mut context = get_context(accounts(0));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0));
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(MIN_REQUIRED_APPROVAL_YOCTO)
        .predecessor_account_id(accounts(0))
        .build());
    contract.storage_deposit(Some(accounts(0)));
}

#[test]
fn test_storage_deposit() {
    let mut context = get_context(accounts(0));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0));
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(MIN_REQUIRED_STORAGE_YOCTO)
        .predecessor_account_id(accounts(0))
        .build());
    contract.storage_deposit(Some(accounts(0)));
    let outcome = contract.storage_deposits.get(&accounts(0));
    let expected = MIN_REQUIRED_STORAGE_YOCTO;
    assert_eq!(outcome, Some(expected));
}

#[test]
fn test_storage_balance_of() {
    let mut context = get_context(accounts(0));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0));
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(MIN_REQUIRED_STORAGE_YOCTO)
        .predecessor_account_id(accounts(0))
        .build());
    contract.storage_deposit(Some(accounts(0)));
    let balance = contract.storage_balance_of(accounts(0));
    assert_eq!(balance, MIN_REQUIRED_STORAGE_YOCTO);
}

#[test]
fn test_storage_withdraw() {
    let mut context = get_context(accounts(0));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0));

    // deposit amount
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(MIN_REQUIRED_STORAGE_YOCTO)
        .predecessor_account_id(accounts(0))
        .build());
    contract.storage_deposit(Some(accounts(0)));

    // withdraw amount
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(ONE_YOCTONEAR) // below func requires a min of 1 yocto attached
        .predecessor_account_id(accounts(0))
        .build());
    contract.storage_withdraw();

    let remaining_amount = contract.storage_balance_of(accounts(0));
    assert_eq!(remaining_amount, NearToken::from_yoctonear(0))
}

#[test]
fn test_remove_sale() {
    let mut context = get_context(accounts(0));
    testing_env!(context.build());
    let mut contract = Contract::new(accounts(0));

    // deposit amount
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(MIN_REQUIRED_STORAGE_YOCTO)
        .predecessor_account_id(accounts(0))
        .build());
    contract.storage_deposit(Some(accounts(0)));

    // add sale
    let token_id = String::from("0n3C0ntr4ctT0Rul3Th3m4ll");
    let sale = Sale {
        owner_id: accounts(0).clone(), //owner of the sale / token
        approval_id: 1,         //approval ID for that token that was given to the market
        nft_contract_id: env::predecessor_account_id().to_string(), //NFT contract the token was minted on
        token_id: token_id.clone(),                                 //the actual token ID
        sale_conditions: SaleCondition {
            token: "btc".to_string(),
            amount: U128::from(10),
        }, //the sale conditions -- price in YOCTO NEAR
        path: "".to_string(),
        token: "".to_string(),
    };
    let nft_contract_id = env::predecessor_account_id();
    let contract_and_token_id = format!("{}{}{}", nft_contract_id, ".", token_id);
    contract.sales.insert(&contract_and_token_id, &sale);
    let owner_token_set = UnorderedSet::new(contract_and_token_id.as_bytes());
    contract
        .by_owner_id
        .insert(&sale.owner_id, &owner_token_set);
    let nft_token_set = UnorderedSet::new(token_id.as_bytes());
    contract
        .by_nft_contract_id
        .insert(&sale.owner_id, &nft_token_set);
    assert_eq!(contract.sales.len(), 1, "Failed to insert sale to contract");

    // remove sale
    testing_env!(context
        .storage_usage(env::storage_usage())
        .attached_deposit(ONE_YOCTONEAR) // below func requires a min of 1 yocto attached
        .predecessor_account_id(accounts(0))
        .build());
    contract.remove_sale(nft_contract_id, token_id);
    assert_eq!(
        contract.sales.len(),
        0,
        "Failed to remove sale from contract"
    );
}
