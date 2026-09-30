use axum::http::HeaderMap;
use serde_json::Value;

use crate::security::{dedupe_key, verify_signature};

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
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn implemented(&self) -> bool {
        true
    }
    fn authenticate(&self, secret: &[u8], headers: &HeaderMap, raw_body: &[u8]) -> bool;
    fn auth_header_names(&self) -> &'static [&'static str] {
        &[]
    }
    fn authenticated_header<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        self.auth_header_names()
            .iter()
            .find_map(|name| headers.get(*name).and_then(|value| value.to_str().ok()))
    }
    fn event_type<'a>(&self, payload: &'a Value) -> &'a str;
    fn event_id(&self, payload: &Value, raw_body: &[u8]) -> String;
    fn dedupe_key(&self, payload: &Value, raw_body: &[u8]) -> String {
        self.event_id(payload, raw_body)
    }
    fn routing_fields(&self, payload: &Value) -> RoutingFields;
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

    fn event_type<'a>(&self, payload: &'a Value) -> &'a str {
        payload
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
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

    fn event_type<'a>(&self, _payload: &'a Value) -> &'a str {
        "unknown"
    }

    fn event_id(&self, _payload: &Value, raw_body: &[u8]) -> String {
        dedupe_key(raw_body)
    }

    fn routing_fields(&self, _payload: &Value) -> RoutingFields {
        RoutingFields::default()
    }
}

static PAYSTACK: PaystackProvider = PaystackProvider;
static APPLE_SERVER_NOTIFICATIONS: UnimplementedProvider = UnimplementedProvider {
    name: "apple_server_notifications",
};
static GOOGLE_PLAY_RTDN: UnimplementedProvider = UnimplementedProvider {
    name: "google_play_rtdn",
};
static APPLE_CONNECT_WEBHOOKS: UnimplementedProvider = UnimplementedProvider {
    name: "apple_connect_webhooks",
};

pub fn provider_for(name: &str) -> Option<&'static dyn Provider> {
    match name {
        "paystack" => Some(&PAYSTACK),
        "apple_server_notifications" => Some(&APPLE_SERVER_NOTIFICATIONS),
        "google_play_rtdn" => Some(&GOOGLE_PLAY_RTDN),
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

pub fn supported_providers() -> [&'static str; 1] {
    ["paystack"]
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
    use sha2::Sha512;

    struct FakeProvider;

    impl Provider for FakeProvider {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn authenticate(&self, _secret: &[u8], _headers: &HeaderMap, _raw_body: &[u8]) -> bool {
            true
        }

        fn event_type<'a>(&self, payload: &'a Value) -> &'a str {
            payload
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
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
        for name in [
            "apple_server_notifications",
            "google_play_rtdn",
            "apple_connect_webhooks",
        ] {
            let provider = provider_for(name).unwrap();
            assert!(!provider.implemented());
            assert!(!provider.authenticate(b"secret", &HeaderMap::new(), b"{}"));
        }
        assert_eq!(supported_providers(), ["paystack"]);
    }
}
