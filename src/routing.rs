use serde_json::Value;

use crate::{
    config::{Config, RouteConfig},
    db::{DatabaseRoute, DatabaseRouteRecord},
    provider::RoutingFields,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchSource {
    AppIdentifier,
    Environment,
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

pub fn database_route<'a>(
    routes: &'a [DatabaseRoute],
    payload: &Value,
) -> Option<&'a DatabaseRoute> {
    let fields = routing_fields_from_payload(payload);
    routes.iter().find(|route| {
        let matcher = crate::config::ExtendedRouteMatcher {
            metadata_app: route.metadata_app.clone(),
            plan_code_prefix: None,
            reference_prefix: route.ref_prefix.clone(),
            app_identifier: None,
            environment: None,
        };
        route_matches(&matcher, &fields)
    })
}

pub fn database_route_records<'a>(
    routes: &'a [DatabaseRouteRecord],
    fields: &RoutingFields,
) -> Option<&'a DatabaseRouteRecord> {
    for preferred_source in [
        MatchSource::MetadataApp,
        MatchSource::PlanCode,
        MatchSource::Reference,
        MatchSource::AppIdentifier,
        MatchSource::Environment,
    ] {
        if let Some(route) = routes
            .iter()
            .find(|route| match_source(&route.matcher, fields).as_ref() == Some(&preferred_source))
        {
            return Some(route);
        }
    }
    None
}

pub fn route_matches(
    matcher: &crate::config::ExtendedRouteMatcher,
    fields: &RoutingFields,
) -> bool {
    let identity_matches = matcher
        .app_identifier
        .as_deref()
        .is_none_or(|value| fields.app_identifier.as_deref() == Some(value))
        && matcher
            .environment
            .as_deref()
            .is_none_or(|value| fields.environment.as_deref() == Some(value));
    let legacy_rules_configured = matcher.metadata_app.is_some()
        || matcher.plan_code_prefix.is_some()
        || matcher.reference_prefix.is_some();
    let legacy_matches = matcher
        .metadata_app
        .as_deref()
        .is_some_and(|value| fields.metadata_app.as_deref() == Some(value))
        || matcher.plan_code_prefix.as_deref().is_some_and(|prefix| {
            fields
                .plan_code
                .as_deref()
                .is_some_and(|value| value.starts_with(prefix))
        })
        || matcher.reference_prefix.as_deref().is_some_and(|prefix| {
            fields
                .reference
                .as_deref()
                .is_some_and(|value| value.starts_with(prefix))
        });
    identity_matches && (!legacy_rules_configured || legacy_matches)
}

pub fn match_source(
    matcher: &crate::config::ExtendedRouteMatcher,
    fields: &RoutingFields,
) -> Option<MatchSource> {
    if !route_matches(matcher, fields) {
        return None;
    }
    if matcher
        .metadata_app
        .as_deref()
        .is_some_and(|value| fields.metadata_app.as_deref() == Some(value))
    {
        return Some(MatchSource::MetadataApp);
    }
    if matcher.plan_code_prefix.as_deref().is_some_and(|prefix| {
        fields
            .plan_code
            .as_deref()
            .is_some_and(|value| value.starts_with(prefix))
    }) {
        return Some(MatchSource::PlanCode);
    }
    if matcher.reference_prefix.as_deref().is_some_and(|prefix| {
        fields
            .reference
            .as_deref()
            .is_some_and(|value| value.starts_with(prefix))
    }) {
        return Some(MatchSource::Reference);
    }
    if matcher
        .app_identifier
        .as_deref()
        .is_some_and(|value| fields.app_identifier.as_deref() == Some(value))
    {
        return Some(MatchSource::AppIdentifier);
    }
    if matcher
        .environment
        .as_deref()
        .is_some_and(|value| fields.environment.as_deref() == Some(value))
    {
        return Some(MatchSource::Environment);
    }
    None
}

pub fn reference(data: &Value) -> Option<String> {
    data.get("reference")
        .and_then(Value::as_str)
        .or_else(|| data.get("subscription_code").and_then(Value::as_str))
        .or_else(|| data.get("customer_code").and_then(Value::as_str))
        .map(str::to_owned)
}

/// The field names here are taken from Paystack's webhook and API examples:
/// <https://paystack.com/docs/payments/webhooks/>
/// <https://paystack.com/docs/api/charge/>
/// <https://paystack.com/docs/payments/subscriptions/>
pub fn decide(config: &Config, payload: &Value) -> RouteDecision {
    decide_with_fields(config, payload, &routing_fields_from_payload(payload))
}

pub fn decide_with_fields(
    config: &Config,
    _payload: &Value,
    fields: &RoutingFields,
) -> RouteDecision {
    for preferred_source in [
        MatchSource::MetadataApp,
        MatchSource::PlanCode,
        MatchSource::Reference,
        MatchSource::AppIdentifier,
        MatchSource::Environment,
    ] {
        if let Some(route) = config.route.iter().find(|route| {
            match_source(&route.matcher.extended(), fields).as_ref() == Some(&preferred_source)
        }) {
            return RouteDecision {
                route: Some(route.clone()),
                source: preferred_source,
            };
        }
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

pub fn routing_fields_from_payload(payload: &Value) -> RoutingFields {
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
        reference: reference(data),
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
    }
}

pub fn metadata_app(data: &Value) -> Option<String> {
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
    use crate::config::{ExtendedRouteMatcher, FallbackConfig, RouteMatcher, SourceConfig};
    use crate::db::DatabaseRoute;
    use std::{collections::HashMap, net::IpAddr};

    fn config() -> Config {
        Config {
            source: HashMap::from([(
                String::from("paystack_main"),
                SourceConfig {
                    provider: "paystack".into(),
                    secret_env: "SECRET".into(),
                    allowed_ips: vec![],
                    audience: None,
                    service_account: None,
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

    #[test]
    fn app_identifier_and_environment_match_together() {
        let mut c = config();
        c.route = vec![RouteConfig {
            name: "store".into(),
            destination_url: "http://store".into(),
            matcher: RouteMatcher::from_extended(ExtendedRouteMatcher {
                app_identifier: Some("com.example.store".into()),
                environment: Some("production".into()),
                ..ExtendedRouteMatcher::default()
            }),
        }];
        let matching = serde_json::json!({
            "data": {"bundleId":"com.example.store","environment":"production"}
        });
        assert_eq!(decide(&c, &matching).route.unwrap().name, "store");
        let wrong_environment = serde_json::json!({
            "data": {"bundleId":"com.example.store","environment":"sandbox"}
        });
        assert!(decide(&c, &wrong_environment).route.is_none());
    }

    #[test]
    fn legacy_route_precedes_environment_only_route() {
        let mut c = config();
        c.route.push(RouteConfig {
            name: "sandbox-store".into(),
            destination_url: "http://store".into(),
            matcher: RouteMatcher::from_extended(ExtendedRouteMatcher {
                environment: Some("sandbox".into()),
                ..ExtendedRouteMatcher::default()
            }),
        });
        let payload = serde_json::json!({
            "data": {"metadata": {"app": "timamu"}, "environment": "sandbox"}
        });
        assert_eq!(decide(&c, &payload).route.unwrap().name, "timamu");
    }

    #[test]
    fn database_routes_match_metadata_or_reference_in_order() {
        let routes = vec![
            DatabaseRoute {
                id: uuid::Uuid::new_v4(),
                name: "timamu".into(),
                target_url: "https://example.invalid/timamu".into(),
                ref_prefix: Some("tm_".into()),
                metadata_app: Some("timamu".into()),
                enabled: true,
            },
            DatabaseRoute {
                id: uuid::Uuid::new_v4(),
                name: "screencrafter".into(),
                target_url: "https://example.invalid/screencrafter".into(),
                ref_prefix: Some("sc_".into()),
                metadata_app: Some("screencrafter".into()),
                enabled: true,
            },
        ];
        assert_eq!(
            database_route(&routes, &serde_json::json!({"data":{"reference":"tm_1"}}))
                .unwrap()
                .name,
            "timamu"
        );
        assert_eq!(
            database_route(
                &routes,
                &serde_json::json!({"data":{"metadata":{"app":"screencrafter"}}})
            )
            .unwrap()
            .name,
            "screencrafter"
        );
        assert!(
            database_route(&routes, &serde_json::json!({"data":{"reference":"other"}})).is_none()
        );
    }

    #[allow(dead_code)]
    fn _ip_type_is_used(_: IpAddr) {}
}
