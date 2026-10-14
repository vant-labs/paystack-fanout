use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use axum::http::HeaderMap;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{TimeZone, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedEventKind {
    Purchase,
    Renew,
    Expire,
    Grace,
    Refund,
    Revoke,
    Upgrade,
    Downgrade,
}

impl NormalizedEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Purchase => "purchase",
            Self::Renew => "renew",
            Self::Expire => "expire",
            Self::Grace => "grace",
            Self::Refund => "refund",
            Self::Revoke => "revoke",
            Self::Upgrade => "upgrade",
            Self::Downgrade => "downgrade",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub schema_version: u8,
    pub provider: String,
    pub event_id: String,
    pub kind: NormalizedEventKind,
    pub account_id: Option<String>,
    pub transaction_id: Option<String>,
    pub original_transaction_id: Option<String>,
    pub purchase_token: Option<String>,
    pub product_id: String,
    pub licence: Option<String>,
    pub app_identifier: String,
    pub environment: String,
    pub expires_at: Option<String>,
    pub raw: Value,
}

impl NormalizedEvent {
    pub fn event_type(&self) -> &'static str {
        self.kind.as_str()
    }

    pub fn purchase_key(&self) -> Option<String> {
        self.original_transaction_id
            .clone()
            .or_else(|| self.purchase_token.clone())
            .or_else(|| self.transaction_id.clone())
    }

    pub fn routing_fields(&self) -> RoutingFields {
        RoutingFields {
            app_identifier: Some(self.app_identifier.clone()),
            environment: Some(self.environment.clone()),
            plan_code: self.licence.clone(),
            ..RoutingFields::default()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PurchaseVerificationRequest {
    pub receipt: String,
    pub product_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProviderRuntimeSettings<'a> {
    pub app_identifier: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub api_base_url: Option<&'a str>,
    pub token_url: Option<&'a str>,
    pub key_id: Option<&'a str>,
    pub issuer_id: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub service_account_key: Option<&'a str>,
    pub service_account: Option<&'a str>,
    pub product_licences: Option<&'a HashMap<String, String>>,
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
    fn normalize_event(&self, _payload: &Value, _raw_body: &[u8]) -> Option<NormalizedEvent> {
        None
    }
    fn normalize_event_with_settings(
        &self,
        payload: &Value,
        raw_body: &[u8],
        _settings: ProviderRuntimeSettings<'_>,
    ) -> Option<NormalizedEvent> {
        self.normalize_event(payload, raw_body)
    }
    async fn enrich_normalized_event(
        &self,
        event: NormalizedEvent,
        _settings: ProviderRuntimeSettings<'_>,
        _http: &reqwest::Client,
    ) -> Result<NormalizedEvent> {
        Ok(event)
    }
    async fn verify_purchase(
        &self,
        _request: &PurchaseVerificationRequest,
        _settings: ProviderRuntimeSettings<'_>,
        _http: &reqwest::Client,
    ) -> Result<NormalizedEvent> {
        bail!(
            "purchase verification is not implemented for {}",
            self.name()
        )
    }
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

#[async_trait]
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

    fn normalize_event(&self, payload: &Value, raw_body: &[u8]) -> Option<NormalizedEvent> {
        apple_normalized_event(payload, raw_body, self.trusted_root, None)
    }

    fn normalize_event_with_settings(
        &self,
        payload: &Value,
        raw_body: &[u8],
        settings: ProviderRuntimeSettings<'_>,
    ) -> Option<NormalizedEvent> {
        apple_normalized_event(payload, raw_body, self.trusted_root, Some(settings))
    }

    async fn verify_purchase(
        &self,
        request: &PurchaseVerificationRequest,
        settings: ProviderRuntimeSettings<'_>,
        http: &reqwest::Client,
    ) -> Result<NormalizedEvent> {
        let receipt = request.receipt.trim();
        if receipt.is_empty() {
            bail!("receipt is empty");
        }
        let signed_claims = if receipt.split('.').count() == 3 {
            verify_signed_payload(receipt, self.trusted_root)
        } else {
            None
        };
        let transaction_id = signed_claims
            .as_ref()
            .and_then(|claims| claims.get("transactionId").and_then(Value::as_str))
            .unwrap_or(receipt)
            .to_owned();
        let signed_transaction = if let Some(base_url) = settings.api_base_url {
            let private_key = settings
                .private_key
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Apple API private key is not configured"))?;
            let issuer_id = settings
                .issuer_id
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Apple API issuer ID is not configured"))?;
            let key_id = settings
                .key_id
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("Apple API key ID is not configured"))?;
            let token = apple_api_token(key_id, issuer_id, private_key, settings.app_identifier)?;
            let url = format!(
                "{}/inApps/v1/transactions/{}",
                base_url.trim_end_matches('/'),
                transaction_id
            );
            let response = http.get(url).bearer_auth(token).send().await?;
            if !response.status().is_success() {
                bail!("Apple transaction lookup returned {}", response.status());
            }
            let response: Value = response.json().await?;
            let signed = response
                .get("signedTransactionInfo")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Apple response has no signed transaction"))?;
            verify_signed_payload(signed, self.trusted_root)
                .ok_or_else(|| anyhow!("Apple transaction signature verification failed"))?;
            signed.to_owned()
        } else {
            signed_claims
                .ok_or_else(|| anyhow!("receipt must be an Apple-signed transaction JWS"))?;
            receipt.to_owned()
        };
        let payload = serde_json::json!({"signedPayload": signed_transaction});
        apple_normalized_event(
            &payload,
            receipt.as_bytes(),
            self.trusted_root,
            Some(settings),
        )
        .ok_or_else(|| anyhow!("Apple transaction does not contain a valid purchase"))
    }
}

fn apple_api_token(
    key_id: &str,
    issuer_id: &str,
    private_key: &str,
    bundle_id: Option<&str>,
) -> Result<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_owned());
    let now = Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iss": issuer_id,
        "iat": now,
        "exp": now + 300,
        "aud": "appstoreconnect-v1"
    });
    if let Some(bundle_id) = bundle_id.filter(|value| !value.is_empty()) {
        claims["bid"] = Value::String(bundle_id.to_owned());
    }
    let key = EncodingKey::from_ec_pem(private_key.as_bytes())
        .map_err(|error| anyhow!("invalid Apple API private key: {error}"))?;
    encode(&header, &claims, &key).map_err(Into::into)
}

fn apple_normalized_event(
    payload: &Value,
    raw_body: &[u8],
    trusted_root: &[u8],
    settings: Option<ProviderRuntimeSettings<'_>>,
) -> Option<NormalizedEvent> {
    let claims = signed_payload_claims(payload)?;
    let data = claims.get("data").unwrap_or(&claims);
    let transaction = data
        .get("signedTransactionInfo")
        .and_then(Value::as_str)
        .and_then(|signed| verify_signed_payload(signed, trusted_root))
        .or_else(|| data.get("transactionInfo").cloned())
        .unwrap_or_else(|| data.clone());
    let notification_type = claims
        .get("notificationType")
        .and_then(Value::as_str)
        .unwrap_or("SUBSCRIBED");
    let subtype = claims.get("subtype").and_then(Value::as_str);
    let mut kind = apple_event_kind(notification_type, subtype, &transaction, data)?;
    if notification_type == "SUBSCRIBED" {
        if transaction.get("revocationDate").is_some() {
            kind = NormalizedEventKind::Revoke;
        } else if date_from_millis(transaction.get("expiresDate"))
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
            .is_some_and(|value| value.with_timezone(&Utc) <= Utc::now())
        {
            kind = NormalizedEventKind::Expire;
        }
    }
    let app_identifier = transaction
        .get("bundleId")
        .and_then(Value::as_str)
        .or_else(|| data.get("bundleId").and_then(Value::as_str))?;
    let environment = transaction
        .get("environment")
        .and_then(Value::as_str)
        .or_else(|| data.get("environment").and_then(Value::as_str))
        .and_then(normalize_environment)?;
    if let Some(settings) = settings.as_ref() {
        let expected_app = settings.app_identifier?;
        let expected_environment = settings.environment?;
        if expected_app != app_identifier {
            return None;
        }
        if normalize_environment(expected_environment) != Some(environment.clone()) {
            return None;
        }
    }
    let product_id = transaction
        .get("productId")
        .and_then(Value::as_str)
        .or_else(|| data.get("productId").and_then(Value::as_str))?;
    let event_id = claims
        .get("notificationUUID")
        .and_then(Value::as_str)
        .or_else(|| transaction.get("transactionId").and_then(Value::as_str))
        .unwrap_or("apple-unknown");
    let licence = settings
        .and_then(|settings| settings.product_licences)
        .and_then(|mapping| mapping.get(product_id))
        .cloned();
    Some(NormalizedEvent {
        schema_version: 1,
        provider: "apple".to_owned(),
        event_id: event_id.to_owned(),
        kind,
        account_id: transaction
            .get("appAccountToken")
            .and_then(Value::as_str)
            .or_else(|| data.get("appAccountToken").and_then(Value::as_str))
            .map(str::to_owned),
        transaction_id: transaction
            .get("transactionId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        original_transaction_id: transaction
            .get("originalTransactionId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        purchase_token: None,
        product_id: product_id.to_owned(),
        licence,
        app_identifier: app_identifier.to_owned(),
        environment,
        expires_at: date_from_millis(transaction.get("expiresDate")),
        raw: serde_json::json!({
            "notification": claims,
            "transaction": transaction,
            "body_sha256": hex::encode(sha2::Sha256::digest(raw_body)),
        }),
    })
}

fn apple_event_kind(
    notification_type: &str,
    subtype: Option<&str>,
    transaction: &Value,
    data: &Value,
) -> Option<NormalizedEventKind> {
    Some(match notification_type {
        "SUBSCRIBED" => NormalizedEventKind::Purchase,
        "DID_RENEW" | "DID_RECOVER" => NormalizedEventKind::Renew,
        "EXPIRED" | "GRACE_PERIOD_EXPIRED" => NormalizedEventKind::Expire,
        "DID_FAIL_TO_RENEW" if subtype == Some("GRACE_PERIOD") => NormalizedEventKind::Grace,
        "DID_FAIL_TO_RENEW" => NormalizedEventKind::Expire,
        "REFUND" => NormalizedEventKind::Refund,
        "REVOKE" => NormalizedEventKind::Revoke,
        "DID_CHANGE_RENEWAL_PREF" => {
            let current = transaction.get("productId").and_then(Value::as_str);
            let next = data
                .get("signedRenewalInfo")
                .and_then(Value::as_str)
                .and_then(decode_jws_claims)
                .and_then(|renewal| {
                    renewal
                        .get("autoRenewProductId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
            if current.is_some() && next.is_some() && current != next.as_deref() {
                NormalizedEventKind::Upgrade
            } else {
                NormalizedEventKind::Downgrade
            }
        }
        _ => return None,
    })
}

fn date_from_millis(value: Option<&Value>) -> Option<String> {
    let millis = value.and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))?;
    Utc.timestamp_millis_opt(millis)
        .single()
        .map(|value| value.to_rfc3339())
}

fn decode_jws_claims(jws: &str) -> Option<Value> {
    let parts = jws.split('.').collect::<Vec<_>>();
    (parts.len() == 3)
        .then(|| URL_SAFE_NO_PAD.decode(parts[1]).ok())
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
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

    fn normalize_event(&self, payload: &Value, _raw_body: &[u8]) -> Option<NormalizedEvent> {
        google_normalized_event(payload, None)
    }

    fn normalize_event_with_settings(
        &self,
        payload: &Value,
        _raw_body: &[u8],
        settings: ProviderRuntimeSettings<'_>,
    ) -> Option<NormalizedEvent> {
        google_normalized_event(payload, Some(settings))
    }

    async fn verify_purchase(
        &self,
        request: &PurchaseVerificationRequest,
        settings: ProviderRuntimeSettings<'_>,
        http: &reqwest::Client,
    ) -> Result<NormalizedEvent> {
        let package = settings
            .app_identifier
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("Google package name is not configured"))?;
        let credential = settings
            .service_account_key
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("Google service-account key is not configured"))?;
        let access_token = google_access_token(
            http,
            credential,
            settings.service_account,
            settings.token_url,
        )
        .await?;
        let base_url = settings
            .api_base_url
            .unwrap_or("https://androidpublisher.googleapis.com");
        let token = request.receipt.trim();
        if token.is_empty() {
            bail!("purchase token is empty");
        }
        let url = format!(
            "{}/androidpublisher/v3/applications/{}/purchases/subscriptionsv2/tokens/{}",
            base_url.trim_end_matches('/'),
            package,
            token
        );
        let response = http.get(url).bearer_auth(&access_token).send().await?;
        let (response, is_subscription) = if response.status().is_success() {
            let purchase: Value = response.json().await?;
            (
                google_subscription_event(
                    package,
                    token,
                    &purchase,
                    settings.environment,
                    settings.product_licences,
                )?,
                true,
            )
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            let product_id = request
                .product_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("product_id is required for a one-time Google purchase"))?;
            let url = format!(
                "{}/androidpublisher/v3/applications/{}/purchases/products/{}/tokens/{}",
                base_url.trim_end_matches('/'),
                package,
                product_id,
                token
            );
            let response = http.get(url).bearer_auth(&access_token).send().await?;
            if !response.status().is_success() {
                bail!("Google purchase lookup returned {}", response.status());
            }
            let purchase: Value = response.json().await?;
            (
                google_product_event(
                    package,
                    token,
                    product_id,
                    &purchase,
                    settings.environment,
                    settings.product_licences,
                )?,
                false,
            )
        } else {
            bail!("Google subscription lookup returned {}", response.status());
        };
        if google_ack_pending(&response.raw) {
            let product = response.product_id.clone();
            let url = if is_subscription {
                format!(
                    "{}/androidpublisher/v3/applications/{}/purchases/subscriptions/{}/tokens/{}:acknowledge",
                    base_url.trim_end_matches('/'),
                    package,
                    product,
                    token
                )
            } else {
                format!(
                    "{}/androidpublisher/v3/applications/{}/purchases/products/{}/tokens/{}:acknowledge",
                    base_url.trim_end_matches('/'),
                    package,
                    product,
                    token
                )
            };
            let ack = http
                .post(url)
                .bearer_auth(&access_token)
                .json(&serde_json::json!({}))
                .send()
                .await?;
            if !ack.status().is_success() {
                bail!("Google purchase acknowledgement returned {}", ack.status());
            }
        }
        Ok(response)
    }

    async fn enrich_normalized_event(
        &self,
        event: NormalizedEvent,
        settings: ProviderRuntimeSettings<'_>,
        http: &reqwest::Client,
    ) -> Result<NormalizedEvent> {
        let Some(token) = event.purchase_token.clone() else {
            return Ok(event);
        };
        let request = PurchaseVerificationRequest {
            receipt: token,
            product_id: (event.product_id != "unknown").then(|| event.product_id.clone()),
        };
        let mut verified = self.verify_purchase(&request, settings, http).await?;
        verified.event_id = event.event_id;
        verified.kind = event.kind;
        Ok(verified)
    }
}

fn google_ack_pending(purchase: &Value) -> bool {
    purchase
        .get("acknowledgementState")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "ACKNOWLEDGEMENT_STATE_PENDING")
        || purchase
            .get("acknowledgementState")
            .and_then(Value::as_u64)
            .is_some_and(|value| value == 0)
}

fn google_normalized_event(
    payload: &Value,
    settings: Option<ProviderRuntimeSettings<'_>>,
) -> Option<NormalizedEvent> {
    let notification = decoded_google_notification(payload)?;
    let package = notification.get("packageName").and_then(Value::as_str)?;
    let event_id = payload
        .pointer("/message/messageId")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .pointer("/message/message_id")
                .and_then(Value::as_str)
        })?;
    let (kind, token, product_id) =
        if let Some(value) = notification.get("subscriptionNotification") {
            let kind = google_subscription_kind(value.get("notificationType")?.as_u64()?)?;
            (
                kind,
                value.get("purchaseToken")?.as_str()?.to_owned(),
                value
                    .get("subscriptionId")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            )
        } else if let Some(value) = notification.get("oneTimeProductNotification") {
            let kind = match value.get("notificationType")?.as_u64()? {
                1 => NormalizedEventKind::Purchase,
                2 => NormalizedEventKind::Refund,
                _ => return None,
            };
            (
                kind,
                value.get("purchaseToken")?.as_str()?.to_owned(),
                value.get("sku")?.as_str()?.to_owned(),
            )
        } else if let Some(value) = notification.get("voidedPurchaseNotification") {
            (
                NormalizedEventKind::Refund,
                value.get("purchaseToken")?.as_str()?.to_owned(),
                "unknown".to_owned(),
            )
        } else {
            return None;
        };
    let (environment, licence) = match settings {
        Some(settings) => (
            settings.environment.and_then(normalize_environment)?,
            settings
                .product_licences
                .and_then(|mapping| mapping.get(&product_id))
                .cloned(),
        ),
        None => ("production".to_owned(), None),
    };
    Some(NormalizedEvent {
        schema_version: 1,
        provider: "google".to_owned(),
        event_id: event_id.to_owned(),
        kind,
        account_id: None,
        transaction_id: None,
        original_transaction_id: None,
        purchase_token: Some(token),
        product_id,
        licence,
        app_identifier: package.to_owned(),
        environment,
        expires_at: None,
        raw: notification,
    })
}

fn google_subscription_kind(notification_type: u64) -> Option<NormalizedEventKind> {
    Some(match notification_type {
        1 | 2 | 7 | 9 => NormalizedEventKind::Renew,
        3 | 12 | 20 => NormalizedEventKind::Revoke,
        4 => NormalizedEventKind::Purchase,
        5 | 6 | 10 | 11 | 22 => NormalizedEventKind::Grace,
        13 => NormalizedEventKind::Expire,
        17 => NormalizedEventKind::Upgrade,
        _ => return None,
    })
}

fn google_subscription_event(
    package: &str,
    token: &str,
    purchase: &Value,
    environment: Option<&str>,
    product_licences: Option<&HashMap<String, String>>,
) -> Result<NormalizedEvent> {
    let line = purchase
        .get("lineItems")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| anyhow!("Google subscription has no line item"))?;
    let product_id = line
        .get("productId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Google subscription has no product ID"))?;
    let state = purchase
        .get("subscriptionState")
        .and_then(Value::as_str)
        .unwrap_or("SUBSCRIPTION_STATE_UNSPECIFIED");
    let kind = match state {
        "SUBSCRIPTION_STATE_ACTIVE" => NormalizedEventKind::Purchase,
        "SUBSCRIPTION_STATE_IN_GRACE_PERIOD" => NormalizedEventKind::Grace,
        "SUBSCRIPTION_STATE_EXPIRED" => NormalizedEventKind::Expire,
        "SUBSCRIPTION_STATE_CANCELED" => NormalizedEventKind::Revoke,
        _ => NormalizedEventKind::Purchase,
    };
    normalized_google_purchase(
        package,
        token,
        product_id,
        kind,
        purchase,
        environment,
        product_licences,
    )
}

fn google_product_event(
    package: &str,
    token: &str,
    product_id: &str,
    purchase: &Value,
    environment: Option<&str>,
    product_licences: Option<&HashMap<String, String>>,
) -> Result<NormalizedEvent> {
    let kind = match purchase.get("purchaseState").and_then(Value::as_u64) {
        Some(1) => NormalizedEventKind::Refund,
        _ => NormalizedEventKind::Purchase,
    };
    normalized_google_purchase(
        package,
        token,
        product_id,
        kind,
        purchase,
        environment,
        product_licences,
    )
}

fn normalized_google_purchase(
    package: &str,
    token: &str,
    product_id: &str,
    kind: NormalizedEventKind,
    purchase: &Value,
    environment: Option<&str>,
    product_licences: Option<&HashMap<String, String>>,
) -> Result<NormalizedEvent> {
    let environment = environment
        .and_then(normalize_environment)
        .ok_or_else(|| anyhow!("Google environment is not configured"))?;
    if environment == "production"
        && (purchase.get("testPurchase").is_some()
            || purchase.get("purchaseType").and_then(Value::as_u64) == Some(0))
    {
        bail!("Google test purchase is not accepted in production");
    }
    Ok(NormalizedEvent {
        schema_version: 1,
        provider: "google".to_owned(),
        event_id: purchase
            .get("latestOrderId")
            .and_then(Value::as_str)
            .unwrap_or(token)
            .to_owned(),
        kind,
        account_id: purchase
            .pointer("/externalAccountIdentifiers/externalAccountId")
            .and_then(Value::as_str)
            .or_else(|| {
                purchase
                    .pointer("/externalAccountIdentifiers/obfuscatedExternalAccountId")
                    .and_then(Value::as_str)
            })
            .map(str::to_owned),
        transaction_id: purchase
            .get("latestOrderId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        original_transaction_id: None,
        purchase_token: Some(token.to_owned()),
        product_id: product_id.to_owned(),
        licence: product_licences
            .and_then(|mapping| mapping.get(product_id))
            .cloned(),
        app_identifier: package.to_owned(),
        environment,
        expires_at: purchase
            .pointer("/lineItems/0/expiryTime")
            .and_then(Value::as_str)
            .map(str::to_owned),
        raw: purchase.clone(),
    })
}

async fn google_access_token(
    http: &reqwest::Client,
    credential: &str,
    configured_email: Option<&str>,
    token_url: Option<&str>,
) -> Result<String> {
    let credential_json: Option<Value> = serde_json::from_str(credential).ok();
    let email = credential_json
        .as_ref()
        .and_then(|value| value.get("client_email").and_then(Value::as_str))
        .or(configured_email)
        .ok_or_else(|| anyhow!("Google service-account email is not configured"))?;
    let private_key = credential_json
        .as_ref()
        .and_then(|value| value.get("private_key").and_then(Value::as_str))
        .ok_or_else(|| anyhow!("Google service-account private key is not configured"))?;
    let token_url = credential_json
        .as_ref()
        .and_then(|value| value.get("token_uri").and_then(Value::as_str))
        .or(token_url)
        .unwrap_or("https://oauth2.googleapis.com/token");
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": email,
        "scope": "https://www.googleapis.com/auth/androidpublisher",
        "aud": token_url,
        "iat": now,
        "exp": now + 3600
    });
    let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
        .map_err(|error| anyhow!("invalid Google service-account key: {error}"))?;
    let assertion = encode(&Header::new(Algorithm::RS256), &claims, &key)?;
    let response = http
        .post(token_url)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("Google OAuth token exchange returned {}", response.status());
    }
    let response: Value = response.json().await?;
    response
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Google OAuth response has no access token"))
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
        "apple" => Some(&APPLE_SERVER_NOTIFICATIONS),
        "google_play_rtdn" => Some(GOOGLE_PLAY_RTDN.get_or_init(GooglePlayRtdnProvider::new)),
        "google" | "google_play" => Some(GOOGLE_PLAY_RTDN.get_or_init(GooglePlayRtdnProvider::new)),
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
        RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, rand_core::OsRng, traits::PublicKeyParts,
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
    fn store_providers_are_implemented() {
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
