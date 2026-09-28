use serde_json::Value;

use crate::config::{Config, RouteConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchSource {
    MetadataApp,
    PlanCode,
    Reference,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub route: Option<RouteConfig>,
    pub source: MatchSource,
}

/// The field names here are taken from Paystack's webhook and API examples:
/// <https://paystack.com/docs/payments/webhooks/>
/// <https://paystack.com/docs/api/charge/>
/// <https://paystack.com/docs/payments/subscriptions/>
pub fn decide(config: &Config, payload: &Value) -> RouteDecision {
    let data = payload.get("data").unwrap_or(payload);
    let metadata_app = metadata_app(data);
    if let Some(route) = config.route.iter().find(|route| {
        route
            .matcher
            .metadata_app
            .as_deref()
            .is_some_and(|needle| metadata_app.as_deref() == Some(needle))
    }) {
        return RouteDecision {
            route: Some(route.clone()),
            source: MatchSource::MetadataApp,
        };
    }

    let plan_code = data
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
                .and_then(|s| s.get("plan"))
                .and_then(extract_plan_code)
        });
    if let Some(route) = config.route.iter().find(|route| {
        route
            .matcher
            .plan_code_prefix
            .as_deref()
            .is_some_and(|prefix| {
                plan_code
                    .as_deref()
                    .is_some_and(|value| value.starts_with(prefix))
            })
    }) {
        return RouteDecision {
            route: Some(route.clone()),
            source: MatchSource::PlanCode,
        };
    }

    let reference = data
        .get("reference")
        .and_then(Value::as_str)
        .or_else(|| data.get("subscription_code").and_then(Value::as_str))
        .or_else(|| data.get("customer_code").and_then(Value::as_str));
    if let Some(route) = config.route.iter().find(|route| {
        route
            .matcher
            .reference_prefix
            .as_deref()
            .is_some_and(|prefix| reference.is_some_and(|value| value.starts_with(prefix)))
    }) {
        return RouteDecision {
            route: Some(route.clone()),
            source: MatchSource::Reference,
        };
    }

    let route = config
        .fallback
        .mode
        .strip_prefix("route:")
        .and_then(|name| config.route.iter().find(|r| r.name == name))
        .cloned();
    RouteDecision {
        route,
        source: MatchSource::Fallback,
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
    use crate::config::{FallbackConfig, RouteMatcher, SourceConfig};
    use std::{collections::HashMap, net::IpAddr};

    fn config() -> Config {
        Config {
            source: HashMap::from([(
                String::from("paystack_main"),
                SourceConfig {
                    provider: "paystack".into(),
                    secret_env: "SECRET".into(),
                    allowed_ips: vec![],
                },
            )]),
            route: vec![
                RouteConfig {
                    name: "timamu".into(),
                    destination_url: "http://timamu".into(),
                    matcher: RouteMatcher {
                        metadata_app: Some("timamu".into()),
                        plan_code_prefix: Some("PLN_tm".into()),
                        reference_prefix: Some("tm_".into()),
                    },
                },
                RouteConfig {
                    name: "screencrafter".into(),
                    destination_url: "http://sc".into(),
                    matcher: RouteMatcher {
                        metadata_app: Some("screencrafter".into()),
                        plan_code_prefix: None,
                        reference_prefix: Some("sc_".into()),
                    },
                },
            ],
            fallback: FallbackConfig {
                mode: "unrouted".into(),
            },
            alerts: None,
            retention_days: 90,
        }
    }

    #[test]
    fn precedence_is_metadata_then_plan_then_reference() {
        let c = config();
        let payload = serde_json::json!({"event":"charge.success","data":{"metadata":{"app":"timamu"},"plan":{"plan_code":"PLN_tm_1"},"reference":"sc_1"}});
        assert_eq!(decide(&c, &payload).route.unwrap().name, "timamu");
        let payload =
            serde_json::json!({"data":{"plan":{"plan_code":"PLN_tm_1"},"reference":"sc_1"}});
        assert_eq!(decide(&c, &payload).route.unwrap().name, "timamu");
        let payload = serde_json::json!({"data":{"reference":"sc_1"}});
        assert_eq!(decide(&c, &payload).route.unwrap().name, "screencrafter");
    }

    #[test]
    fn custom_fields_and_subscription_fields_are_supported() {
        let c = config();
        let payload = serde_json::json!({"data":{"metadata":{"custom_fields":[{"variable_name":"app","value":"screencrafter"}]}}});
        assert_eq!(decide(&c, &payload).route.unwrap().name, "screencrafter");
        let payload =
            serde_json::json!({"data":{"subscription":{"plan":{"plan_code":"PLN_tm_monthly"}}}});
        assert_eq!(decide(&c, &payload).route.unwrap().name, "timamu");
    }

    #[test]
    fn fallback_is_unrouted() {
        let c = config();
        let payload = serde_json::json!({"data":{"reference":"other"}});
        let decision = decide(&c, &payload);
        assert!(decision.route.is_none());
        assert_eq!(decision.source, MatchSource::Fallback);
    }

    #[allow(dead_code)]
    fn _ip_type_is_used(_: IpAddr) {}
}
