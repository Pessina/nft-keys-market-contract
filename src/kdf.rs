use crate::*;

use std::str::FromStr;
use bitcoin::{Address, CompressedPublicKey, Network};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField, sec1::{FromEncodedPoint, ToEncodedPoint}}, EncodedPoint, Scalar, Secp256k1, U256
};
use near_sdk::{near_bindgen, PublicKey};
use sha3::{Digest, Keccak256, Sha3_256};

pub fn derive_btc_address(
    public_key_hex: &str,
    network: Network,
) -> Result<String, Box<dyn std::error::Error>> {
    let public_key_bytes = hex::decode(public_key_hex)?;
    let public_key = CompressedPublicKey::from_slice(&public_key_bytes)?;
    let address = Address::p2wpkh(&public_key, network);
    Ok(address.to_string())
}

pub fn derive_eth_address(public_key_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key_hex = if public_key_hex.starts_with("04") {
        &public_key_hex[2..]
    } else {
        public_key_hex
    };

    let pub_key_bytes = hex::decode(key_hex)?;

    let mut hasher = Keccak256::new();
    hasher.update(&pub_key_bytes);
    let hash = hasher.finalize();

    let eth_address = &hash[12..];
    
    Ok(format!("0x{}", hex::encode(eth_address)))
}

const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_epsilon(predecessor_id: &str, path: &str) -> Scalar {
    let derivation_path = format!("{EPSILON_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    let bytes = U256::from_be_slice(hash.as_slice());
    Scalar::from_repr(bytes.to_be_byte_array()).expect("Derived epsilon value falls outside of the field")
}

pub fn derive_key(public_key: <Secp256k1 as CurveArithmetic>::AffinePoint, epsilon: Scalar) -> <Secp256k1 as CurveArithmetic>::AffinePoint {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

pub fn near_public_key_to_affine_point(pk: near_sdk::PublicKey) -> <Secp256k1 as CurveArithmetic>::AffinePoint {
    let mut bytes = pk.into_bytes();
    bytes[0] = 0x04;
    let point = EncodedPoint::from_bytes(bytes).unwrap();
    <Secp256k1 as CurveArithmetic>::AffinePoint::from_encoded_point(&point).unwrap()
}

#[near_bindgen]
impl Contract {
    pub fn get_address(&self, path: String, chain: String, signer_id: String) -> String {
        let derived_key = self.derived_public_key(path, signer_id)
            .expect("Failed to derive public key");

        let key_bytes = derived_key.as_bytes();
        let public_key = hex::encode(&key_bytes[1..]);

        match chain.as_str() {
            "BTC" => {
                let mut compressed_bytes = vec![0x02];
                if key_bytes[64] % 2 == 1 {
                    compressed_bytes[0] = 0x03;
                }
                compressed_bytes.extend_from_slice(&key_bytes[1..33]);
                let compressed_key = hex::encode(compressed_bytes);
                
                derive_btc_address(&compressed_key, Network::Testnet)
                    .expect("Failed to derive BTC address")
            },
            "ETH" => derive_eth_address(&public_key)
                .expect("Failed to derive ETH address"),
            _ => panic!("Unsupported chain")
        }
    }

    #[handle_result]
    pub fn derived_public_key(
        &self,
        path: String,
        signer_id: String
    ) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let public_key = "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3".to_string();

        let epsilon = derive_epsilon(&signer_id, &path);
        let derived_public_key =
            derive_key(near_public_key_to_affine_point(near_sdk::PublicKey::from_str(&public_key).unwrap()), epsilon);
        let encoded_point = derived_public_key.to_encoded_point(false);
        let slice: &[u8] = &encoded_point.as_bytes()[1..65];
        let mut data: Vec<u8> = vec![near_sdk::CurveType::SECP256K1 as u8];
        data.extend(slice.to_vec());
        PublicKey::try_from(data).map_err(|_| "Failed to convert derived public key to NEAR public key".into())
    }
}