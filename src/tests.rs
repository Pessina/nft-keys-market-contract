use crate::{sale::Sale, SaleCondition};
use crate::krnl_auth::{KrnlAuth, KrnlPayload};

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

#[test]
fn test_krnl_validation() {
    let context = get_context(accounts(0));
    testing_env!(context.build());
    let contract = Contract::new(accounts(0));

    // Test data
    
    let payload = KrnlPayload {
        function_params: "0x00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000001".to_string(),
        sender: "4174678c78fEaFd778c1ff319D5D326701449b25".to_string(),
        auth: KrnlAuth {
            kernel_param_objects: "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000".to_string(),
            kernel_responses: "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000105000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000731303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022334b36617974374b614256534b474c526b32476739677262515735705450523743330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            auth: "0x00000000000000000000000000000000000000000000000000000000000000a01e8087402deb673531e8f83d09263385e7b379c1d683fa5c0bf05bf2ed16bd7f0000000000000000000000000000000000000000000000000000000000000120d31ac7417d5e29a6fc72e9e47a608447d6471841ef36e745d79533e2222e9f5100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000041d571e8719bd290b72889f548db7e51122fc4ec06c1a4580940e3ed5bb10087a76382d88eb9b4b4bf29391a1ab57919c33f256aa80347b93b153ef24a410f67e41b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410fbe4016d44945d8ceb21e85398b6e0e75a80143ac852c00d5c03886e567617d1efdb86dc5e9f3077361d07068fb66ddd2336dfe5488971a83519faba7378dce1b00000000000000000000000000000000000000000000000000000000000000".to_string(),
        }
    };

    assert!(contract.is_krnl_authorized(payload));
}

#[test]
fn test_decode_kernel_responses() {
    let context = get_context(accounts(0));
    testing_env!(context.build());
    let contract = Contract::new(accounts(0));

    // Test kernel_responses data
    let kernel_responses = "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000010c0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002a74623171703437737967376e71323677336d656871353934797139336376637834656174727672746d6300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000732353834343236000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();

    let kernel_response = contract.decode_kernel_responses(kernel_responses);

    // Assert the decoded values match expected
    assert_eq!(kernel_response.address, "2584426");
    assert_eq!(kernel_response.balance, "tb1qp47syg7nq26w3mehq594yq93cvcx4eatrvrtmc");
}

#[test]
fn test_eth_derived_public_key() {
    let context = get_context(accounts(0));
    testing_env!(context.build());
    let contract = Contract::new(accounts(0));
    let address = contract.get_address("{\"chain\":60,\"domain\":\"\",\"meta\":{\"path\":\"eth\"}}".to_string(), "ETH".to_string(), "test-multichain.testnet".to_string());
    assert_eq!(address, "0xbd369f12f46c24837aa6bb4f8abede5cbee6e35a", "ETH address should match expected value");
}

#[test]
fn test_btc_derived_public_key() {
    let context = get_context(accounts(0));
    testing_env!(context.build());
    let contract = Contract::new(accounts(0));
    let address = contract.get_address("{\"chain\":0,\"domain\":\"\",\"meta\":{\"path\":\"btc\"}}".to_string(), "BTC".to_string(), "test-multichain.testnet".to_string());
    assert_eq!(address, "tb1qp47syg7nq26w3mehq594yq93cvcx4eatrvrtmc", "BTC address should match expected value");
}



