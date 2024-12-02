use hex;
use k256::ecdsa::{Signature as K256Signature, RecoveryId, VerifyingKey}; 
use near_sdk::{
    log, 
    serde::{Serialize, Deserialize},
};
use sha3::{Digest, Keccak256};
use ethabi::{decode, ethereum_types::H160, ParamType, Token};
use schemars::JsonSchema;

use crate::*;

const TOKEN_AUTHORITY_ADDRESS: &str = "0b3D85B517375E88Beb482E21EA4f14fEc302a62"; 

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct KrnlAuth {
    pub auth: String,
    pub kernel_responses: String, 
    pub kernel_param_objects: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct KrnlPayload {
    pub function_params: String,
    pub sender: String,
    pub auth: KrnlAuth,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct KernelResponse {
    pub balance: String,
    pub wallet: String,
}

pub fn decode_hex(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.trim_start_matches("0x")).unwrap()
}

pub fn verify_recovered_address(recovered_addr: [u8; 20], token_authority: &str) -> bool {
    let token_authority_bytes: [u8; 20] = hex::decode(token_authority)
        .unwrap()[..20]
        .try_into()
        .unwrap();
    recovered_addr == token_authority_bytes
}

pub fn create_digest(tokens: &[Token]) -> [u8; 32] {
    let encoded = ethabi::encode(tokens);
    Keccak256::digest(&encoded).into()
}

pub fn recover_eth_address(message_hash: &[u8; 32], signature: &[u8]) -> Option<[u8; 20]> {
    if signature.len() != 65 {
        log!("Invalid signature length: {}", signature.len());
        return None;
    }

    let (r_s_bytes, v_byte) = signature.split_at(64);
    let v = v_byte[0];

    let signature = K256Signature::try_from(r_s_bytes).map_err(|_| {
        log!("Invalid signature format");
        None::<K256Signature>
    }).unwrap();

    let recovery_id = RecoveryId::try_from(if v >= 27 { v - 27 } else { v }).map_err(|_| {
        log!("Invalid recovery ID");
        None::<RecoveryId>
    }).unwrap();

    let verifying_key = VerifyingKey::recover_from_prehash(
        message_hash,
        &signature,
        recovery_id
    ).map_err(|_| {
        log!("Failed to recover public key");
        None::<VerifyingKey>
    }).unwrap();

    let public_key = verifying_key.to_encoded_point(false);
    let mut hasher = Keccak256::new();
    hasher.update(&public_key.as_bytes()[1..]);
    let hash = hasher.finalize();
    
    Some(hash[12..32].try_into().unwrap())
}

pub fn decode_auth(auth_data: &str) -> Option<(Vec<u8>, [u8; 32], Vec<u8>, [u8; 32], bool)> {
    if !auth_data.starts_with("0x") {
        log!("Auth data must start with 0x");
        return None;
    }

    let auth_bytes = decode_hex(auth_data);

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

#[near_bindgen]
impl Contract {
    pub fn is_krnl_authorized(&self, krnl_payload: KrnlPayload) -> bool {
        let function_params = decode_hex(&krnl_payload.function_params);
        let sender = decode_hex(&krnl_payload.sender);

        // 1. Auth Decoding
        let auth_data = match decode_auth(&krnl_payload.auth.auth) {
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
        let kernel_responses = decode_hex(&krnl_payload.auth.kernel_responses);
        let kernel_responses_tokens = vec![
            Token::Bytes(kernel_responses),
            Token::Address(H160::from_slice(&sender))
        ];
        let kernel_responses_digest = create_digest(&kernel_responses_tokens);
        
        log!("LogKernelResponsesVerification:");
        log!("digest: {}", hex::encode(&kernel_responses_digest));
    
        if let Some(recovered_addr) = recover_eth_address(&kernel_responses_digest, &kernel_responses_sig) {
            log!("recovered: {}", hex::encode(&recovered_addr));
            if !verify_recovered_address(recovered_addr, TOKEN_AUTHORITY_ADDRESS) {
                log!("Invalid recovered address for kernel responses");
                return false;
            }
        } else {
            log!("Failed to recover address from kernel responses signature");
            return false;
        }
    
        // 3. Kernel Params Verification
        let kernel_params = decode_hex(&krnl_payload.auth.kernel_param_objects);
        let kernel_params_tokens = vec![
            Token::Bytes(kernel_params),
            Token::Address(H160::from_slice(&sender))
        ];
        let calculated_kernel_params_digest = create_digest(&kernel_params_tokens);
        
        log!("LogKernelParamsVerification:");
        log!("expected: {}", hex::encode(&kernel_params_digest));
        log!("actual: {}", hex::encode(&calculated_kernel_params_digest));
        
        if calculated_kernel_params_digest != kernel_params_digest {
            return false;
        }
    
        // 4. Function Call Verification
        let function_params_tokens = vec![Token::Bytes(function_params)];
        let function_params_digest = create_digest(&function_params_tokens);
        
        log!("LogFunctionCallVerification:");
        log!("paramsDigest: {}", hex::encode(&function_params_digest));
        
        let data_tokens = vec![
            Token::FixedBytes(function_params_digest.to_vec()),
            Token::FixedBytes(kernel_params_digest.to_vec()),
            Token::Address(H160::from_slice(&sender)),
            Token::FixedBytes(nonce.to_vec()),
            Token::Bool(final_opinion)
        ];
    
        let data_digest = create_digest(&data_tokens);
    
        if let Some(recovered_addr) = recover_eth_address(&data_digest, &signature_token) {
            log!("recovered: {}", hex::encode(&recovered_addr));
            if !verify_recovered_address(recovered_addr, TOKEN_AUTHORITY_ADDRESS) {
                return false;
            }
        } else {
            return false;
        }
    
        true
    }


    pub fn decode_kernel_responses(&self, kernel_responses: String) -> KernelResponse {
        let kernel_responses_bytes = decode_hex(&kernel_responses);

        let param_types = vec![
            ParamType::Array(Box::new(ParamType::Tuple(vec![
                ParamType::Uint(256),    // kernelId
                ParamType::Bytes,        // result 
                ParamType::String,       // err
            ])))
        ];

        let tokens = decode(&param_types, &kernel_responses_bytes).unwrap();

        if let Token::Array(responses) = &tokens[0] {
            if let Token::Tuple(fields) = &responses[0] {
                if let Token::Bytes(bytes) = &fields[1] {
                    let result = hex::encode(bytes);
                    
                    let result_bytes = hex::decode(&result).unwrap();
                    let result_param_types = vec![
                        ParamType::Tuple(vec![
                            ParamType::String,  // balance
                            ParamType::String   // wallet
                        ])
                    ];
                    let result_tokens = decode(&result_param_types, &result_bytes).unwrap();

                    if let Token::Tuple(fields) = &result_tokens[0] {
                        if let (Token::String(balance), Token::String(wallet)) = (&fields[0], &fields[1]) {
                            return KernelResponse {
                                balance: balance.to_string(),
                                wallet: wallet.to_string()
                            };
                        }
                    }
                }
            }
        }

        KernelResponse {
            balance: "".to_string(),
            wallet: "".to_string()
        }
    }
}