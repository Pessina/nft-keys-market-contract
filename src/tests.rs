use crate::{sale::Sale, SaleCondition};
#[cfg(test)]
use crate::Contract;
use ethabi::{ethereum_types::{H160, U256}, Address};
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
    use hex;
    use k256::ecdsa::{Signature as K256Signature, RecoveryId, VerifyingKey};
    use near_sdk::log;
    use sha3::{Digest, Keccak256};
    use ethabi::{decode, ParamType, Token, ethereum_types::H160};

    #[derive(Debug)]
    struct KrnlPayload {
        auth: String,
        kernel_responses: String,
        kernel_param_objects: String,
    }

    fn recover_eth_address(message_hash: &[u8; 32], signature: &[u8]) -> Option<[u8; 20]> {
        if signature.len() != 65 {
            log!("Invalid signature length: {}", signature.len());
            return None;
        }

        let (r_s_bytes, v_byte) = signature.split_at(64);
        let v = v_byte[0];

        // Create signature object
        let signature: K256Signature = K256Signature::try_from(r_s_bytes).map_err(|_| {
            log!("Invalid signature format");
            None::<K256Signature>
        }).unwrap();

        // Create recovery ID
        let recovery_id = RecoveryId::try_from(if v >= 27 { v - 27 } else { v }).map_err(|_| {
            log!("Invalid recovery ID");
            None::<RecoveryId>
        }).unwrap();

        // Recover the public key
        let verifying_key = VerifyingKey::recover_from_prehash(
            message_hash,
            &signature,
            recovery_id
        ).map_err(|_| {
            log!("Failed to recover public key");
            None::<VerifyingKey>
        }).unwrap();

        // Convert to Ethereum address
        let public_key = verifying_key.to_encoded_point(false);
        let mut hasher = Keccak256::new();
        hasher.update(&public_key.as_bytes()[1..]);
        let hash = hasher.finalize();
        
        Some(hash[12..32].try_into().unwrap())
    }

    fn validate_krnl_payload(function_params: &str, payload: &KrnlPayload, sender: &[u8; 20]) -> bool {
        // 1. Auth Decoding
        let auth_data = match decode_auth(&payload.auth) {
            Some(data) => {
                log!("LogDecodingAuth: true");
                data
            },
            None => {
                log!("LogDecodingAuth: false");
                return false
            }
        };

        let (kernel_responses_sig, kernel_params_digest, signature_token, nonce, final_opinion) = auth_data;
        if !final_opinion {
            return false;
        }

        log!("LogIsAuthorized");
        log!("kernel_responses_sig: {}", hex::encode(&kernel_responses_sig).to_uppercase());
        log!("kernel_params_digest: {}", hex::encode(&kernel_params_digest).to_uppercase());
        log!("signature_token: {}", hex::encode(&signature_token).to_uppercase());
        log!("nonce: {}", hex::encode(&nonce).to_uppercase());
        log!("final_opinion: {}", if final_opinion { "True" } else { "False" });

        // 2. Kernel Responses Verification
        let kernel_responses = hex::decode(payload.kernel_responses.trim_start_matches("0x")).unwrap();
        
        let kernel_responses_tokens = vec![
            Token::Bytes(kernel_responses),
            Token::Address(H160::from_slice(sender))
        ];
        
        let kernel_responses_data = ethabi::encode(&kernel_responses_tokens);
        let kernel_responses_digest: [u8; 32] = Keccak256::digest(&kernel_responses_data).into();
        
        log!("LogKernelResponsesVerification:");
        log!("digest: {}", hex::encode(&kernel_responses_digest));

        if let Some(recovered_addr) = recover_eth_address(&kernel_responses_digest, &kernel_responses_sig) {
            log!("recovered: {}", hex::encode(&recovered_addr));
            let token_authority = hex::decode(TOKEN_AUTHORITY_ADDRESS).unwrap();
            let token_authority_bytes: [u8; 20] = token_authority[..20].try_into().unwrap();
            if recovered_addr != token_authority_bytes {
                log!("Invalid recovered address for kernel responses");
                return false;
            }
        } else {
            log!("Failed to recover address from kernel responses signature");
            return false;
        }

        // 3. Kernel Params Verification
        let kernel_params = hex::decode(payload.kernel_param_objects.trim_start_matches("0x")).unwrap();
        
        let kernel_params_tokens = vec![
            Token::Bytes(kernel_params),
            Token::Address(H160::from_slice(sender))
        ];
        
        let kernel_params_data = ethabi::encode(&kernel_params_tokens);
        let calculated_kernel_params_digest: [u8; 32] = Keccak256::digest(&kernel_params_data).into();
        
        log!("LogKernelParamsVerification:");
        log!("expected: {}", hex::encode(&kernel_params_digest));
        log!("actual: {}", hex::encode(&calculated_kernel_params_digest));
        
        if calculated_kernel_params_digest != kernel_params_digest {
            return false;
        }

        // 4. Function Call Verification
        let function_params = hex::decode(function_params.trim_start_matches("0x")).unwrap();

        let function_params_tokens = vec![Token::Bytes(function_params)];
        let function_params_encoded = ethabi::encode(&function_params_tokens);
        let function_params_digest: [u8; 32] = Keccak256::digest(&function_params_encoded).into();
        
        log!("LogFunctionCallVerification:");
        log!("paramsDigest: {}", hex::encode(&function_params_digest));
        
        let data_tokens = vec![
            Token::FixedBytes(function_params_digest.to_vec()),
            Token::FixedBytes(kernel_params_digest.to_vec()),
            Token::Address(H160::from_slice(sender)),
            Token::FixedBytes(nonce.to_vec()),
            Token::Bool(final_opinion)
        ];

        let data_encoded = ethabi::encode(&data_tokens);
        let data_digest: [u8; 32] = Keccak256::digest(&data_encoded).into();

        if let Some(recovered_addr) = recover_eth_address(&data_digest, &signature_token) {
            log!("recovered: {}", hex::encode(&recovered_addr));
            let token_authority = hex::decode(TOKEN_AUTHORITY_ADDRESS).unwrap();
            let token_authority_bytes: [u8; 20] = token_authority[..20].try_into().unwrap();
            if recovered_addr != token_authority_bytes {
                return false;
            }
        } else {
            return false;
        }

        true
    }

    fn decode_auth(auth_data: &str) -> Option<(Vec<u8>, [u8; 32], Vec<u8>, [u8; 32], bool)> {
        if !auth_data.starts_with("0x") {
            log!("Auth data must start with 0x");
            return None;
        }

        let auth_bytes = hex::decode(&auth_data[2..]).map_err(|e| {
            log!("Failed to decode hex string: {:?}", e);
            None::<Vec<u8>>
        }).unwrap();

        let param_types = vec![
            ParamType::Bytes,
            ParamType::FixedBytes(32),
            ParamType::Bytes,
            ParamType::FixedBytes(32),
            ParamType::Bool,
        ];

        let tokens = decode(&param_types, &auth_bytes).map_err(|e| {
            log!("Failed to decode ABI data: {:?}", e);
            None::<Vec<Token>>
        }).unwrap();

        if tokens.len() != 5 {
            log!("Invalid number of decoded tokens");
            return None;
        }

        let kernel_responses_sig = match &tokens[0] {
            Token::Bytes(bytes) => bytes.clone(),
            _ => {
                log!("Invalid kernel_responses_sig type");
                return None;
            }
        };

        let kernel_params_digest = match &tokens[1] {
            Token::FixedBytes(bytes) => {
                let mut digest = [0u8; 32];
                digest.copy_from_slice(bytes);
                digest
            }
            _ => {
                log!("Invalid kernel_params_digest type");
                return None;
            }
        };

        let signature_token = match &tokens[2] {
            Token::Bytes(bytes) => bytes.clone(),
            _ => {
                log!("Invalid signature_token type");
                return None;
            }
        };

        let nonce = match &tokens[3] {
            Token::FixedBytes(bytes) => {
                let mut n = [0u8; 32];
                n.copy_from_slice(bytes);
                n
            }
            _ => {
                log!("Invalid nonce type");
                return None;
            }
        };

        let final_opinion = match &tokens[4] {
            Token::Bool(b) => *b,
            _ => {
                log!("Invalid final_opinion type");
                return None;
            }
        };

        Some((
            kernel_responses_sig,
            kernel_params_digest,
            signature_token,
            nonce,
            final_opinion
        ))
    }

    const TOKEN_AUTHORITY_ADDRESS: &str = "0b3D85B517375E88Beb482E21EA4f14fEc302a62"; 
    let sender: [u8; 20] = hex::decode("4174678c78fEaFd778c1ff319D5D326701449b25").unwrap().try_into().unwrap();

    // Test data
    let params = "0x00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000001".to_string();

    let payload = KrnlPayload {
        kernel_param_objects: "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000".to_string(),
        kernel_responses: "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000105000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000731303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022334b36617974374b614256534b474c526b32476739677262515735705450523743330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        auth: "0x00000000000000000000000000000000000000000000000000000000000000a01e8087402deb673531e8f83d09263385e7b379c1d683fa5c0bf05bf2ed16bd7f0000000000000000000000000000000000000000000000000000000000000120d31ac7417d5e29a6fc72e9e47a608447d6471841ef36e745d79533e2222e9f5100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000041d571e8719bd290b72889f548db7e51122fc4ec06c1a4580940e3ed5bb10087a76382d88eb9b4b4bf29391a1ab57919c33f256aa80347b93b153ef24a410f67e41b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410fbe4016d44945d8ceb21e85398b6e0e75a80143ac852c00d5c03886e567617d1efdb86dc5e9f3077361d07068fb66ddd2336dfe5488971a83519faba7378dce1b00000000000000000000000000000000000000000000000000000000000000".to_string()
    };

    assert!(validate_krnl_payload(&params, &payload, &sender));
}
