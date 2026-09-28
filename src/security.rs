use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

type HmacSha512 = Hmac<Sha512>;

pub fn verify_signature(secret: &[u8], body: &[u8], provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(provided) else {
        return false;
    };
    let Ok(mut mac) = HmacSha512::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(&expected_bytes).into()
}

pub fn dedupe_key(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn bearer_matches(token: &str, provided: Option<&str>) -> bool {
    let Some(value) = provided.and_then(|v| v.strip_prefix("Bearer ")) else {
        return false;
    };
    Sha256::digest(token.as_bytes())
        .as_slice()
        .ct_eq(Sha256::digest(value.as_bytes()).as_slice())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_cases() {
        let secret = b"sk_test_secret";
        let body = br#"{"event":"charge.success"}"#;
        let mut mac = HmacSha512::new_from_slice(secret).unwrap();
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        assert!(verify_signature(secret, body, Some(&signature)));
        assert!(!verify_signature(
            secret,
            br#"{"event":"tampered"}"#,
            Some(&signature)
        ));
        assert!(!verify_signature(b"wrong", body, Some(&signature)));
        assert!(!verify_signature(secret, body, None));
    }
}
