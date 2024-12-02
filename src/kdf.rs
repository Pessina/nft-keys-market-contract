use bitcoin::{Address, CompressedPublicKey, Network};
use sha3::{Digest, Keccak256};

pub fn naj_to_pub_key(naj_pub_key: &str, compress: bool) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = naj_pub_key.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid NAJ public key format".into());
    }
    
    let decoded = bs58::decode(parts[1]).into_vec()?;
    let uncompressed_pub_key = format!("04{}", hex::encode(&decoded));

    if !compress {
        return Ok(uncompressed_pub_key);
    }

    // Handle compression
    if !uncompressed_pub_key.starts_with("04") {
        return Err("Invalid public key format".into());
    }

    let pub_key_hex = &uncompressed_pub_key[2..];
    if pub_key_hex.len() != 128 {
        return Err("Invalid uncompressed public key length".into());
    }

    let x = &pub_key_hex[0..64];
    let y = &pub_key_hex[64..];

    
    let last_byte = u8::from_str_radix(&y[y.len()-2..], 16)?;
    let prefix = if last_byte % 2 == 0 { "02" } else { "03" };

    Ok(format!("{}{}", prefix, x))
}


pub fn derive_btc_address_and_public_key(
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
