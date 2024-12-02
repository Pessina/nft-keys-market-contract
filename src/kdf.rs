use crate::*;

use std::str::FromStr;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField, sec1::{FromEncodedPoint, ToEncodedPoint}}, EncodedPoint, Scalar, Secp256k1, U256
};
use near_sdk::{near_bindgen, PublicKey};
use sha3::{Digest, Keccak256, Sha3_256};

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Bitcoin,
    Testnet,
}

pub fn derive_btc_address(
    public_key_hex: &str,
    network: Network,
) -> String {
    use sha2::{Digest, Sha256};
    use ripemd::Ripemd160;
    use bech32::{self, u5, ToBase32, Variant};

    let public_key_bytes = hex::decode(public_key_hex)
        .expect("Failed to decode public key hex string");
    
    let sha256_hash = Sha256::digest(&public_key_bytes);
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    let hrp = match network {
        Network::Bitcoin => "bc",
        Network::Testnet => "tb",
    };
    
    let witness_version = u5::try_from_u8(0)
        .expect("Failed to convert witness version to u5");
    let program_base32 = ripemd160_hash.to_base32();
    let mut data = vec![witness_version];

    data.extend(program_base32);
    let address = bech32::encode(hrp, data, Variant::Bech32)
        .expect("Failed to encode BTC address in Bech32 format");

    address
}


pub fn derive_eth_address(public_key_hex: &str) -> String {
    let key_hex = if public_key_hex.starts_with("04") {
        &public_key_hex[2..]
    } else {
        public_key_hex
    };

    let pub_key_bytes = hex::decode(key_hex)
        .expect("Failed to decode public key hex string");

    let mut hasher = Keccak256::new();
    hasher.update(&pub_key_bytes);
    let hash = hasher.finalize();

    let eth_address = &hash[12..];
    
    format!("0x{}", hex::encode(eth_address))
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
    let point = EncodedPoint::from_bytes(bytes)
        .expect("Failed to create encoded point from public key bytes");
    <Secp256k1 as CurveArithmetic>::AffinePoint::from_encoded_point(&point)
        .expect("Failed to convert encoded point to affine point")
}

#[near_bindgen]
impl Contract {
    pub fn get_address(&self, path: String, chain: String, signer_id: String) -> String {
        let derived_key = self.derived_public_key(path, signer_id);

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
            },
            "ETH" => derive_eth_address(&public_key),
            _ => panic!("Unsupported chain")
        }
    }

    pub fn derived_public_key(
        &self,
        path: String,
        signer_id: String
    ) -> PublicKey {
        let public_key = "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3".to_string();

        let epsilon = derive_epsilon(&signer_id, &path);
        let derived_public_key =
            derive_key(near_public_key_to_affine_point(near_sdk::PublicKey::from_str(&public_key)
                .expect("Failed to parse public key string")), epsilon);
        let encoded_point = derived_public_key.to_encoded_point(false);
        let slice: &[u8] = &encoded_point.as_bytes()[1..65];
        let mut data: Vec<u8> = vec![near_sdk::CurveType::SECP256K1 as u8];
        data.extend(slice.to_vec());
        near_sdk::PublicKey::try_from(data)
            .expect("Failed to create NEAR public key from derived key data")
    }
}