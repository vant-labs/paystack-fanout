use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::random;

fn key_from_env() -> anyhow::Result<[u8; 32]> {
    let value = std::env::var("MASTER_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("FANOUT_ENCRYPTION_KEY"))
        .map_err(|_| anyhow::anyhow!("MASTER_ENCRYPTION_KEY is required"))?;
    let bytes = hex::decode(&value)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .or_else(|| {
            STANDARD
                .decode(value)
                .ok()
                .filter(|bytes| bytes.len() == 32)
        })
        .ok_or_else(|| {
            anyhow::anyhow!("MASTER_ENCRYPTION_KEY must be 32 bytes in hex or base64")
        })?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid encryption key length"))
}

pub fn encrypt(plaintext: &str) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(&key_from_env()?)
        .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    let nonce_bytes = random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("secret encryption failed"))?;
    Ok(STANDARD.encode([nonce_bytes.as_slice(), ciphertext.as_slice()].concat()))
}

pub fn decrypt(encoded: &str) -> anyhow::Result<String> {
    let value = STANDARD.decode(encoded)?;
    anyhow::ensure!(value.len() > 12, "encrypted secret is invalid");
    let cipher = Aes256Gcm::new_from_slice(&key_from_env()?)
        .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&value[..12]), &value[12..])
        .map_err(|_| anyhow::anyhow!("secret decryption failed"))?;
    Ok(String::from_utf8(plaintext)?)
}
