use std::fmt;

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::http::{HeaderMap, HeaderValue, header};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::random;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "fanout_session";
pub const SESSION_DAYS: i64 = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Role {
    Owner,
    Admin,
    Viewer,
}

impl Role {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn can_write(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_manage(self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn can_manage_users(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionUser {
    pub id: Uuid,
    pub email: String,
    pub initial: String,
    pub role: Role,
    pub can_write: bool,
    pub can_manage: bool,
    #[serde(skip)]
    pub csrf_token: String,
    #[serde(skip)]
    pub session_token: String,
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        password.len() >= 12,
        "password must be at least 12 characters"
    );
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

pub fn random_token() -> String {
    hex::encode(random::<[u8; 32]>())
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn csrf_matches(expected: &str, provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    Sha256::digest(expected.as_bytes())
        .as_slice()
        .ct_eq(Sha256::digest(provided.as_bytes()).as_slice())
        .into()
}

pub fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == SESSION_COOKIE && !value.is_empty()).then(|| value.to_owned())
    })
}

pub fn session_cookie(token: &str, secure: bool) -> HeaderValue {
    let secure_flag = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{secure_flag}",
        SESSION_DAYS * 86_400
    ))
    .expect("session cookie is valid")
}

pub fn clear_session_cookie(secure: bool) -> HeaderValue {
    let secure_flag = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure_flag}"
    ))
    .expect("session cookie is valid")
}

pub fn verify_totp(secret: &str, code: &str, timestamp: u64) -> bool {
    if code.len() != 6 || !code.bytes().all(|value| value.is_ascii_digit()) {
        return false;
    }
    let Ok(key) = BASE32_NOPAD.decode(secret.as_bytes()) else {
        return false;
    };
    let counter = (timestamp / 30).to_be_bytes();
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&key) else {
        return false;
    };
    mac.update(&counter);
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let value = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let expected = format!("{:06}", value % 1_000_000);
    expected.as_bytes().ct_eq(code.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hashes_are_verifiable() {
        let encoded = hash_password("a secure password").unwrap();
        assert!(verify_password("a secure password", &encoded));
        assert!(!verify_password("a different password", &encoded));
    }

    #[test]
    fn csrf_comparison_is_exact() {
        assert!(csrf_matches("token", Some("token")));
        assert!(!csrf_matches("token", Some("Token")));
        assert!(!csrf_matches("token", None));
    }
}
