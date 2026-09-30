use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::http::HeaderMap;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use x509_parser::{pem::parse_x509_pem, prelude::parse_x509_certificate, public_key::PublicKey};

use crate::security::{dedupe_key, verify_hmac_sha256_signature, verify_signature};

/// The normalized fields a provider exposes to the routing layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingFields {
    pub metadata_app: Option<String>,
    pub plan_code: Option<String>,
    pub reference: Option<String>,
    pub app_identifier: Option<String>,
    pub environment: Option<String>,
}

/// Provider boundary for authentication and provider-specific event metadata.
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn implemented(&self) -> bool {
        true
    }
    fn secret_required(&self) -> bool {
        true
    }
    fn authenticate(&self, secret: &[u8], headers: &HeaderMap, raw_body: &[u8]) -> bool;
    async fn authenticate_with_settings(
        &self,
        secret: &[u8],
        headers: &HeaderMap,
        raw_body: &[u8],
        _settings: ProviderSettings<'_>,
    ) -> bool {
        self.authenticate(secret, headers, raw_body)
    }
    fn auth_header_names(&self) -> &'static [&'static str] {
        &[]
    }
    fn authenticated_header<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        self.auth_header_names()
            .iter()
            .find_map(|name| headers.get(*name).and_then(|value| value.to_str().ok()))
    }
    fn event_type(&self, payload: &Value) -> String;
    fn event_id(&self, payload: &Value, raw_body: &[u8]) -> String;
    fn dedupe_key(&self, payload: &Value, raw_body: &[u8]) -> String {
        self.event_id(payload, raw_body)
    }
    fn routing_fields(&self, payload: &Value) -> RoutingFields;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderSettings<'a> {
    pub audience: Option<&'a str>,
    pub service_account: Option<&'a str>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PaystackProvider;

impl Provider for PaystackProvider {
    fn name(&self) -> &'static str {
        "paystack"
    }

    fn authenticate(&self, secret: &[u8], headers: &HeaderMap, raw_body: &[u8]) -> bool {
        verify_signature(
            secret,
            raw_body,
            headers
                .get("x-paystack-signature")
                .and_then(|value| value.to_str().ok()),
        )
    }

    fn auth_header_names(&self) -> &'static [&'static str] {
        &["x-paystack-signature"]
    }

    fn event_type(&self, payload: &Value) -> String {
        payload
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned()
    }

    fn event_id(&self, payload: &Value, raw_body: &[u8]) -> String {
        event_id_from_paths(payload, &["id", "data.id"]).unwrap_or_else(|| dedupe_key(raw_body))
    }

    fn dedupe_key(&self, _payload: &Value, raw_body: &[u8]) -> String {
        dedupe_key(raw_body)
    }

    fn routing_fields(&self, payload: &Value) -> RoutingFields {
        paystack_fields(payload)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AppleServerNotificationsProvider {
    trusted_root: &'static [u8],
}

impl AppleServerNotificationsProvider {
    pub const fn with_trusted_root(trusted_root: &'static [u8]) -> Self {
        Self { trusted_root }
    }
}

impl Provider for AppleServerNotificationsProvider {
    fn name(&self) -> &'static str {
        "apple_server_notifications"
    }

    fn implemented(&self) -> bool {
        true
    }

    fn secret_required(&self) -> bool {
        false
    }

    fn authenticate(&self, _secret: &[u8], _headers: &HeaderMap, raw_body: &[u8]) -> bool {
        serde_json::from_slice::<Value>(raw_body)
            .ok()
            .and_then(|payload| {
                payload
                    .get("signedPayload")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .is_some_and(|signed_payload| {
                verify_signed_payload(&signed_payload, self.trusted_root).is_some()
            })
    }

    fn event_type(&self, payload: &Value) -> String {
        let Some(claims) = signed_payload_claims(payload) else {
            return "unknown".to_owned();
        };
        let Some(notification_type) = claims.get("notificationType").and_then(Value::as_str) else {
            return "unknown".to_owned();
        };
        claims
            .get("subtype")
            .and_then(Value::as_str)
            .filter(|subtype| !subtype.is_empty())
            .map(|subtype| format!("{notification_type}:{subtype}"))
            .unwrap_or_else(|| notification_type.to_owned())
    }

    fn event_id(&self, payload: &Value, raw_body: &[u8]) -> String {
        signed_payload_claims(payload)
            .and_then(|claims| {
                claims
                    .get("notificationUUID")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| dedupe_key(raw_body))
    }

    fn routing_fields(&self, payload: &Value) -> RoutingFields {
        let Some(claims) = signed_payload_claims(payload) else {
            return RoutingFields::default();
        };
        let data = claims.get("data").unwrap_or(&claims);
        RoutingFields {
            app_identifier: data
                .get("bundleId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            environment: data
                .get("environment")
                .and_then(Value::as_str)
                .and_then(normalize_environment),
            ..RoutingFields::default()
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AppStoreConnectWebhooksProvider;

impl Provider for AppStoreConnectWebhooksProvider {
    fn name(&self) -> &'static str {
        "apple_connect_webhooks"
    }

    fn authenticate(&self, secret: &[u8], headers: &HeaderMap, raw_body: &[u8]) -> bool {
        verify_hmac_sha256_signature(
            secret,
            raw_body,
            headers
                .get("x-apple-signature")
                .and_then(|value| value.to_str().ok()),
        )
    }

    fn auth_header_names(&self) -> &'static [&'static str] {
        &["x-apple-signature"]
    }

    fn event_type(&self, payload: &Value) -> String {
        ["eventType", "type", "data.eventType", "data.type"]
            .iter()
            .find_map(|path| string_at_path(payload, path))
            .unwrap_or_else(|| "unknown".to_owned())
    }

    fn event_id(&self, payload: &Value, raw_body: &[u8]) -> String {
        ["eventId", "id", "data.eventId", "data.id"]
            .iter()
            .find_map(|path| string_at_path(payload, path))
            .unwrap_or_else(|| dedupe_key(raw_body))
    }

    fn routing_fields(&self, payload: &Value) -> RoutingFields {
        RoutingFields {
            app_identifier: [
                "appId",
                "app_id",
                "bundleId",
                "bundle_id",
                "data.appId",
                "data.app_id",
                "data.bundleId",
                "data.bundle_id",
                "data.attributes.appId",
                "data.attributes.bundleId",
                "data.relationships.app.data.id",
            ]
            .iter()
            .find_map(|path| string_at_path(payload, path)),
            ..RoutingFields::default()
        }
    }
}

pub struct GooglePlayRtdnProvider {
    keys: RwLock<HashMap<String, DecodingKey>>,
    refreshed_at: Mutex<Option<Instant>>,
    client: reqwest::Client,
    key_url: &'static str,
}

#[derive(Debug, Deserialize)]
struct GooglePushClaims {
    email: String,
    email_verified: bool,
}

impl GooglePlayRtdnProvider {
    const KEY_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
    const KEY_URL: &'static str = "https://www.googleapis.com/oauth2/v1/certs";

    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            refreshed_at: Mutex::new(None),
            client: reqwest::Client::new(),
            key_url: Self::KEY_URL,
        }
    }

    async fn key_for(&self, kid: &str) -> Option<DecodingKey> {
        let cached_key = self.keys.read().await.get(kid).cloned();
        let cache_fresh = self
            .refreshed_at
            .lock()
            .ok()
            .and_then(|value| *value)
            .is_some_and(|value| value.elapsed() < Self::KEY_CACHE_TTL);
        if cache_fresh && cached_key.is_some() {
            return cached_key;
        }
        self.refresh_keys().await;
        self.keys.read().await.get(kid).cloned()
    }

    async fn refresh_keys(&self) {
        let Ok(response) = self.client.get(self.key_url).send().await else {
            return;
        };
        if !response.status().is_success() {
            return;
        }
        let Ok(certificates) = response.json::<HashMap<String, String>>().await else {
            return;
        };
        let keys = certificates
            .into_iter()
            .filter_map(|(kid, certificate)| {
                rsa_decoding_key(certificate.as_bytes()).map(|key| (kid, key))
            })
            .collect::<HashMap<_, _>>();
        if keys.is_empty() {
            return;
        }
        *self.keys.write().await = keys;
        if let Ok(mut refreshed_at) = self.refreshed_at.lock() {
            *refreshed_at = Some(Instant::now());
        }
    }

    #[cfg(test)]
    fn with_keys(keys: HashMap<String, DecodingKey>) -> Self {
        Self {
            keys: RwLock::new(keys),
            refreshed_at: Mutex::new(Some(Instant::now())),
            client: reqwest::Client::new(),
            key_url: Self::KEY_URL,
        }
    }
}

impl Default for GooglePlayRtdnProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for GooglePlayRtdnProvider {
    fn name(&self) -> &'static str {
        "google_play_rtdn"
    }

    fn secret_required(&self) -> bool {
        false
    }

    fn authenticate(&self, _secret: &[u8], _headers: &HeaderMap, _raw_body: &[u8]) -> bool {
        false
    }

    async fn authenticate_with_settings(
        &self,
        _secret: &[u8],
        headers: &HeaderMap,
        _raw_body: &[u8],
        settings: ProviderSettings<'_>,
    ) -> bool {
        let Some(audience) = settings.audience.filter(|value| !value.is_empty()) else {
            return false;
        };
        let Some(service_account) = settings.service_account.filter(|value| !value.is_empty())
        else {
            return false;
        };
        let Some(token) = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
        else {
            return false;
        };
        let Ok(header) = decode_header(token) else {
            return false;
        };
        if header.alg != Algorithm::RS256 {
            return false;
        }
        let Some(kid) = header.kid.as_deref() else {
            return false;
        };
        let Some(key) = self.key_for(kid).await else {
            return false;
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);
        let Ok(token_data) = decode::<GooglePushClaims>(token, &key, &validation) else {
            return false;
        };
        token_data.claims.email_verified && token_data.claims.email == service_account
    }

    fn auth_header_names(&self) -> &'static [&'static str] {
        &["authorization"]
    }

    fn event_type(&self, payload: &Value) -> String {
        let Some(notification) = decoded_google_notification(payload) else {
            return "unknown".to_owned();
        };
        for (key, prefix) in [
            ("subscriptionNotification", "subscription"),
            ("oneTimeProductNotification", "one_time_product"),
        ] {
            if let Some(notification_type) = notification
                .get(key)
                .and_then(|value| value.get("notificationType"))
                .and_then(Value::as_u64)
            {
                return format!("{prefix}:{notification_type}");
            }
        }
        if notification.get("voidedPurchaseNotification").is_some() {
            return "voided_purchase".to_owned();
        }
        if notification
            .get("pendingPurchaseCancellationNotification")
            .is_some()
        {
            return "pending_refund_review".to_owned();
        }
        if notification.get("testNotification").is_some() {
            return "test".to_owned();
        }
        "unknown".to_owned()
    }

    fn event_id(&self, payload: &Value, raw_body: &[u8]) -> String {
        payload
            .pointer("/message/messageId")
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .pointer("/message/message_id")
                    .and_then(Value::as_str)
            })
            .map(str::to_owned)
            .unwrap_or_else(|| dedupe_key(raw_body))
    }

    fn dedupe_key(&self, payload: &Value, raw_body: &[u8]) -> String {
        self.event_id(payload, raw_body)
    }

    fn routing_fields(&self, payload: &Value) -> RoutingFields {
        decoded_google_notification(payload)
            .and_then(|notification| {
                notification
                    .get("packageName")
                    .and_then(Value::as_str)
                    .map(|package| RoutingFields {
                        app_identifier: Some(package.to_owned()),
                        ..RoutingFields::default()
                    })
            })
            .unwrap_or_default()
    }
}

fn rsa_decoding_key(certificate: &[u8]) -> Option<DecodingKey> {
    let (_, pem) = parse_x509_pem(certificate).ok()?;
    let (_, certificate) = parse_x509_certificate(&pem.contents).ok()?;
    match certificate.public_key().parsed().ok()? {
        PublicKey::RSA(key) => Some(
            DecodingKey::from_rsa_components(
                &URL_SAFE_NO_PAD.encode(key.modulus),
                &URL_SAFE_NO_PAD.encode(key.exponent),
            )
            .ok()?,
        ),
        _ => None,
    }
}

fn decoded_google_notification(payload: &Value) -> Option<Value> {
    let encoded = payload.pointer("/message/data")?.as_str()?;
    let decoded = STANDARD.decode(encoded).ok()?;
    serde_json::from_slice(&decoded).ok()
}

#[derive(Debug, Clone, Copy)]
struct UnimplementedProvider {
    name: &'static str,
}

impl Provider for UnimplementedProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn implemented(&self) -> bool {
        false
    }

    fn authenticate(&self, _secret: &[u8], _headers: &HeaderMap, _raw_body: &[u8]) -> bool {
        false
    }

    fn event_type(&self, _payload: &Value) -> String {
        "unknown".to_owned()
    }

    fn event_id(&self, _payload: &Value, raw_body: &[u8]) -> String {
        dedupe_key(raw_body)
    }

    fn routing_fields(&self, _payload: &Value) -> RoutingFields {
        RoutingFields::default()
    }
}

static PAYSTACK: PaystackProvider = PaystackProvider;
static APPLE_SERVER_NOTIFICATIONS: AppleServerNotificationsProvider =
    AppleServerNotificationsProvider::with_trusted_root(include_bytes!(
        "certs/apple/AppleRootCA-G3.cer"
    ));
static APPLE_CONNECT_WEBHOOKS: AppStoreConnectWebhooksProvider = AppStoreConnectWebhooksProvider;
static GOOGLE_PLAY_RTDN: OnceLock<GooglePlayRtdnProvider> = OnceLock::new();

pub fn provider_for(name: &str) -> Option<&'static dyn Provider> {
    match name {
        "paystack" => Some(&PAYSTACK),
        "apple_server_notifications" => Some(&APPLE_SERVER_NOTIFICATIONS),
        "google_play_rtdn" => Some(GOOGLE_PLAY_RTDN.get_or_init(GooglePlayRtdnProvider::new)),
        "apple_connect_webhooks" => Some(&APPLE_CONNECT_WEBHOOKS),
        _ => None,
    }
}

pub fn known_providers() -> [&'static str; 4] {
    [
        "paystack",
        "apple_server_notifications",
        "google_play_rtdn",
        "apple_connect_webhooks",
    ]
}

pub fn supported_providers() -> [&'static str; 4] {
    [
        "paystack",
        "apple_server_notifications",
        "apple_connect_webhooks",
        "google_play_rtdn",
    ]
}

fn string_at_path(payload: &Value, path: &str) -> Option<String> {
    path.split('.')
        .try_fold(payload, |value, key| value.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn event_id_from_paths(payload: &Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        let value = path
            .split('.')
            .try_fold(payload, |value, key| value.get(key))?;
        value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_u64().map(|value| value.to_string()))
    })
}

fn signed_payload_claims(payload: &Value) -> Option<Value> {
    let signed_payload = payload.get("signedPayload")?.as_str()?;
    let parts = signed_payload.split('.').collect::<Vec<_>>();
    (parts.len() == 3).then(|| {
        URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()
            .and_then(|claims| serde_json::from_slice(&claims).ok())
    })?
}

fn normalize_environment(environment: &str) -> Option<String> {
    match environment {
        "Production" | "production" => Some("production".to_owned()),
        "Sandbox" | "sandbox" => Some("sandbox".to_owned()),
        _ => None,
    }
}

fn verify_signed_payload(signed_payload: &str, trusted_root_der: &[u8]) -> Option<Value> {
    let parts = signed_payload.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .ok()
        .and_then(|value| serde_json::from_slice::<Value>(&value).ok())?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return None;
    }
    let certificates = header
        .get("x5c")?
        .as_array()?
        .iter()
        .map(|value| STANDARD.decode(value.as_str()?).ok())
        .collect::<Option<Vec<_>>>()?;
    let claims = URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|value| serde_json::from_slice::<Value>(&value).ok())?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
    let leaf = verify_certificate_chain(&certificates, trusted_root_der)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &leaf)
        .verify(signing_input.as_bytes(), &signature)
        .ok()?;
    Some(claims)
}

fn verify_certificate_chain(certificates: &[Vec<u8>], trusted_root_der: &[u8]) -> Option<Vec<u8>> {
    if certificates.len() < 2 {
        return None;
    }
    let (_, trusted_root) = parse_x509_certificate(trusted_root_der).ok()?;
    if !trusted_root.validity().is_valid() || trusted_root.verify_signature(None).is_err() {
        return None;
    }
    for (index, certificate_der) in certificates.iter().enumerate() {
        let (_, certificate) = parse_x509_certificate(certificate_der).ok()?;
        if !certificate.validity().is_valid() {
            return None;
        }
        if index + 1 < certificates.len() {
            let (_, issuer) = parse_x509_certificate(&certificates[index + 1]).ok()?;
            if !issuer.is_ca()
                || certificate.issuer() != issuer.subject()
                || certificate
                    .verify_signature(Some(issuer.public_key()))
                    .is_err()
            {
                return None;
            }
        } else if certificate_der.as_slice() == trusted_root_der {
            if certificate.verify_signature(None).is_err() {
                return None;
            }
        } else if !certificate.is_ca()
            || certificate.issuer() != trusted_root.subject()
            || certificate
                .verify_signature(Some(trusted_root.public_key()))
                .is_err()
        {
            return None;
        }
    }
    let (_, leaf) = parse_x509_certificate(&certificates[0]).ok()?;
    Some(leaf.public_key().subject_public_key.data.to_vec())
}

fn paystack_fields(payload: &Value) -> RoutingFields {
    let data = payload.get("data").unwrap_or(payload);
    RoutingFields {
        metadata_app: metadata_app(data),
        plan_code: data
            .get("plan")
            .and_then(extract_plan_code)
            .or_else(|| {
                data.pointer("/subscription/plan/plan_code")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| {
                data.get("subscription")
                    .and_then(Value::as_object)
                    .and_then(|subscription| subscription.get("plan"))
                    .and_then(extract_plan_code)
            }),
        reference: ["reference", "subscription_code", "customer_code"]
            .iter()
            .find_map(|key| data.get(*key).and_then(Value::as_str).map(str::to_owned)),
        ..store_fields(payload)
    }
}

fn store_fields(payload: &Value) -> RoutingFields {
    let data = payload.get("data").unwrap_or(payload);
    RoutingFields {
        app_identifier: ["appIdentifier", "bundleId", "packageName"]
            .iter()
            .find_map(|key| data.get(*key).and_then(Value::as_str).map(str::to_owned))
            .or_else(|| {
                payload
                    .get("packageName")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }),
        environment: ["environment", "env"]
            .iter()
            .find_map(|key| data.get(*key).and_then(Value::as_str).map(str::to_owned))
            .or_else(|| {
                payload
                    .get("environment")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }),
        ..RoutingFields::default()
    }
}

fn metadata_app(data: &Value) -> Option<String> {
    let metadata = data.get("metadata")?;
    if let Some(app) = metadata.get("app").and_then(Value::as_str) {
        return Some(app.to_owned());
    }
    metadata
        .get("custom_fields")?
        .as_array()?
        .iter()
        .find_map(|field| {
            (field.get("variable_name").and_then(Value::as_str) == Some("app"))
                .then(|| {
                    field
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .flatten()
        })
}

fn extract_plan_code(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Object(map) => map
            .get("plan_code")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    };
    use rsa::{
        RsaPrivateKey,
        pkcs1::EncodeRsaPrivateKey,
        rand_core::OsRng,
        traits::PublicKeyParts,
    };
    use sha2::Sha512;
    use time::{Duration, OffsetDateTime};

    struct FakeProvider;

    impl Provider for FakeProvider {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn authenticate(&self, _secret: &[u8], _headers: &HeaderMap, _raw_body: &[u8]) -> bool {
            true
        }

        fn event_type(&self, payload: &Value) -> String {
            payload
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned()
        }

        fn event_id(&self, payload: &Value, _raw_body: &[u8]) -> String {
            payload["id"].as_str().unwrap_or("missing").to_owned()
        }

        fn routing_fields(&self, payload: &Value) -> RoutingFields {
            RoutingFields {
                app_identifier: payload["app"].as_str().map(str::to_owned),
                environment: payload["environment"].as_str().map(str::to_owned),
                ..RoutingFields::default()
            }
        }
    }

    #[test]
    fn a_second_provider_can_supply_the_boundary_contract() {
        let provider = FakeProvider;
        let payload = serde_json::json!({
            "id": "evt_1",
            "kind": "notification",
            "app": "com.example.app",
            "environment": "sandbox"
        });
        assert!(provider.authenticate(b"secret", &HeaderMap::new(), b"body"));
        assert_eq!(provider.event_type(&payload), "notification");
        assert_eq!(provider.event_id(&payload, b"body"), "evt_1");
        assert_eq!(
            provider.routing_fields(&payload).app_identifier.as_deref(),
            Some("com.example.app")
        );
    }

    #[test]
    fn paystack_authentication_remains_hmac_sha512() {
        let body = br#"{"event":"charge.success"}"#;
        let mut mac = Hmac::<Sha512>::new_from_slice(b"secret").unwrap();
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert("x-paystack-signature", signature.parse().unwrap());
        assert!(PaystackProvider.authenticate(b"secret", &headers, body));
    }

    #[test]
    fn store_providers_are_explicitly_unimplemented() {
        let apple = provider_for("apple_server_notifications").unwrap();
        assert!(apple.implemented());
        let app_store_connect = provider_for("apple_connect_webhooks").unwrap();
        assert!(app_store_connect.implemented());
        let google = provider_for("google_play_rtdn").unwrap();
        assert!(google.implemented());
        assert_eq!(
            supported_providers(),
            [
                "paystack",
                "apple_server_notifications",
                "apple_connect_webhooks",
                "google_play_rtdn"
            ]
        );
    }

    #[test]
    fn app_store_connect_webhooks_verify_signature_and_extract_fields() {
        let provider = AppStoreConnectWebhooksProvider;
        let payload = serde_json::json!({
            "data": {
                "type": "buildUploadStateUpdated",
                "id": "event-1",
                "attributes": {"appId": "123456789"}
            }
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let secret = b"app-store-connect-secret";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
        mac.update(&body);
        let signature = format!("hmacsha256={}", hex::encode(mac.finalize().into_bytes()));
        let mut headers = HeaderMap::new();
        headers.insert("x-apple-signature", signature.parse().unwrap());
        assert!(provider.authenticate(secret, &headers, &body));
        assert_eq!(provider.event_type(&payload), "buildUploadStateUpdated");
        assert_eq!(provider.event_id(&payload, &body), "event-1");
        assert_eq!(
            provider.routing_fields(&payload).app_identifier.as_deref(),
            Some("123456789")
        );
        assert!(!provider.authenticate(b"wrong", &headers, &body));
        let mut tampered = body.clone();
        tampered[0] = b' ';
        assert!(!provider.authenticate(secret, &headers, &tampered));
    }

    fn google_test_provider() -> (GooglePlayRtdnProvider, RsaPrivateKey) {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let decoding_key = DecodingKey::from_rsa_components(
            &URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be()),
            &URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be()),
        )
        .unwrap();
        (
            GooglePlayRtdnProvider::with_keys(HashMap::from([(
                "test-key".to_owned(),
                decoding_key,
            )])),
            private_key,
        )
    }

    fn google_test_token(
        private_key: &RsaPrivateKey,
        audience: &str,
        service_account: &str,
        expiration: i64,
    ) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        let claims = serde_json::json!({
            "aud": audience,
            "email": service_account,
            "email_verified": true,
            "exp": expiration,
            "iss": "https://accounts.google.com"
        });
        let private_der = private_key.to_pkcs1_der().unwrap();
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_der(private_der.as_bytes()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn google_play_rtdn_authenticates_google_push_jwt_claims() {
        let (provider, private_key) = google_test_provider();
        let audience = "https://example.test/in/google_main";
        let service_account = "pubsub@example.iam.gserviceaccount.com";
        let token = google_test_token(
            &private_key,
            audience,
            service_account,
            chrono::Utc::now().timestamp() + 3600,
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert!(
            provider
                .authenticate_with_settings(
                    &[],
                    &headers,
                    b"{}",
                    ProviderSettings {
                        audience: Some(audience),
                        service_account: Some(service_account),
                    },
                )
                .await
        );
        assert!(
            !provider
                .authenticate_with_settings(
                    &[],
                    &headers,
                    b"{}",
                    ProviderSettings {
                        audience: Some("https://example.test/wrong"),
                        service_account: Some(service_account),
                    },
                )
                .await
        );
        assert!(
            !provider
                .authenticate_with_settings(
                    &[],
                    &headers,
                    b"{}",
                    ProviderSettings {
                        audience: Some(audience),
                        service_account: Some("other@example.iam.gserviceaccount.com"),
                    },
                )
                .await
        );
    }

    #[tokio::test]
    async fn google_play_rtdn_rejects_expired_and_unsigned_tokens() {
        let (provider, private_key) = google_test_provider();
        let audience = "https://example.test/in/google_main";
        let service_account = "pubsub@example.iam.gserviceaccount.com";
        let expired = google_test_token(&private_key, audience, service_account, 1);
        let unsigned = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUudGVzdC9pbi9nb29nbGVfbWFpbiJ9.".to_owned();
        for token in [expired, unsigned] {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
            assert!(
                !provider
                    .authenticate_with_settings(
                        &[],
                        &headers,
                        b"{}",
                        ProviderSettings {
                            audience: Some(audience),
                            service_account: Some(service_account),
                        },
                    )
                    .await
            );
        }
    }

    #[test]
    fn google_play_rtdn_decodes_pubsub_data_and_message_id() {
        let provider = GooglePlayRtdnProvider::new();
        let payload: Value =
            serde_json::from_str(include_str!("../tests/fixtures/google_play_rtdn.json")).unwrap();
        assert_eq!(provider.event_type(&payload), "subscription:4");
        assert_eq!(provider.event_id(&payload, b"body"), "google-message-1");
        assert_eq!(provider.dedupe_key(&payload, b"body"), "google-message-1");
        assert_eq!(
            provider.routing_fields(&payload).app_identifier.as_deref(),
            Some("com.example.app")
        );

        for (notification, event_type) in [
            (
                serde_json::json!({"voidedPurchaseNotification": {"orderId": "order-1"}}),
                "voided_purchase",
            ),
            (
                serde_json::json!({"pendingPurchaseCancellationNotification": {"productId": "product-1"}}),
                "pending_refund_review",
            ),
            (
                serde_json::json!({"testNotification": {"version": "1.0"}}),
                "test",
            ),
        ] {
            let payload = serde_json::json!({
                "message": {
                    "data": STANDARD.encode(serde_json::to_vec(&notification).unwrap()),
                    "messageId": "google-message-2"
                }
            });
            assert_eq!(provider.event_type(&payload), event_type);
        }
    }

    struct SignedNotification {
        provider: AppleServerNotificationsProvider,
        payload: Value,
        root_der: Vec<u8>,
    }

    fn signed_notification(root_expired: bool) -> SignedNotification {
        let now = OffsetDateTime::now_utc();
        let mut root_params = CertificateParams::new(vec!["test-root".to_owned()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        if root_expired {
            root_params.not_before = now - Duration::days(2);
            root_params.not_after = now - Duration::days(1);
        }
        let root_key = KeyPair::generate().unwrap();
        let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();
        let root_der = root.der().to_vec();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["test-leaf".to_owned()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &root).unwrap();
        let leaf_der = leaf.der().to_vec();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "ES256",
                "x5c": [STANDARD.encode(&leaf_der), STANDARD.encode(&root_der)]
            }))
            .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "notificationType": "DID_RENEW",
                "subtype": "VOLUNTARY",
                "notificationUUID": "notification-1",
                "data": {
                    "bundleId": "com.example.app",
                    "environment": "Sandbox"
                }
            }))
            .unwrap(),
        );
        let signing_input = format!("{header}.{claims}");
        let signing_key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &leaf_key.serialize_der(),
            &SystemRandom::new(),
        )
        .unwrap();
        let signature = signing_key
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .unwrap();
        let signed_payload = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        );
        let payload = serde_json::json!({"signedPayload": signed_payload});
        let trusted_root = Box::leak(root_der.clone().into_boxed_slice());
        SignedNotification {
            provider: AppleServerNotificationsProvider::with_trusted_root(trusted_root),
            payload,
            root_der,
        }
    }

    #[test]
    fn apple_server_notifications_verify_chain_and_extract_fields() {
        let notification = signed_notification(false);
        let body = serde_json::to_vec(&notification.payload).unwrap();
        assert!(
            notification
                .provider
                .authenticate(&[], &HeaderMap::new(), &body)
        );
        assert_eq!(
            notification.provider.event_type(&notification.payload),
            "DID_RENEW:VOLUNTARY"
        );
        assert_eq!(
            notification.provider.event_id(&notification.payload, &body),
            "notification-1"
        );
        assert_eq!(
            notification.provider.routing_fields(&notification.payload),
            RoutingFields {
                app_identifier: Some("com.example.app".to_owned()),
                environment: Some("sandbox".to_owned()),
                ..RoutingFields::default()
            }
        );
    }

    #[test]
    fn apple_server_notifications_reject_tampered_expired_and_untrusted_payloads() {
        let notification = signed_notification(false);
        let body = serde_json::to_vec(&notification.payload).unwrap();
        let mut tampered = notification.payload.clone();
        let signed_payload = tampered["signedPayload"].as_str().unwrap();
        let mut parts = signed_payload.split('.');
        let header = parts.next().unwrap();
        let _claims = parts.next().unwrap();
        let signature = parts.next().unwrap();
        let changed_claims = URL_SAFE_NO_PAD.encode(br#"{"notificationType":"REFUND"}"#);
        tampered["signedPayload"] = format!("{header}.{changed_claims}.{signature}").into();
        assert!(!notification.provider.authenticate(
            &[],
            &HeaderMap::new(),
            &serde_json::to_vec(&tampered).unwrap()
        ));

        let expired = signed_notification(true);
        assert!(!expired.provider.authenticate(
            &[],
            &HeaderMap::new(),
            &serde_json::to_vec(&expired.payload).unwrap()
        ));

        let untrusted_root = signed_notification(false).root_der;
        let trusted_root = Box::leak(untrusted_root.into_boxed_slice());
        let untrusted_provider = AppleServerNotificationsProvider::with_trusted_root(trusted_root);
        assert!(!untrusted_provider.authenticate(&[], &HeaderMap::new(), &body));
    }
}
