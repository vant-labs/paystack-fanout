use serde_json::Value;

use crate::security::verify_signature;

/// Provider boundary for future Stripe and Flutterwave adapters. Paystack is
/// the only implementation in this repository today.
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn verify_signature(&self, secret: &[u8], raw_body: &[u8], signature: Option<&str>) -> bool;
    fn event_type<'a>(&self, payload: &'a Value) -> &'a str;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PaystackProvider;

impl Provider for PaystackProvider {
    fn name(&self) -> &'static str {
        "paystack"
    }

    fn verify_signature(&self, secret: &[u8], raw_body: &[u8], signature: Option<&str>) -> bool {
        verify_signature(secret, raw_body, signature)
    }

    fn event_type<'a>(&self, payload: &'a Value) -> &'a str {
        payload
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    }
}
