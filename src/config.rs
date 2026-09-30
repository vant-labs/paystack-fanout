use std::{collections::HashMap, env, net::IpAddr, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub source: HashMap<String, SourceConfig>,
    pub route: Vec<RouteConfig>,
    pub fallback: FallbackConfig,
    #[serde(default)]
    pub alerts: Option<AlertsConfig>,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_retention_days() -> u32 {
    90
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceConfig {
    pub provider: String,
    pub secret_env: String,
    #[serde(default)]
    pub allowed_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub destination_url: String,
    #[serde(rename = "match")]
    pub matcher: RouteMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteMatcher {
    pub metadata_app: Option<String>,
    pub plan_code_prefix: Option<String>,
    pub reference_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExtendedRouteMatcher {
    #[serde(default)]
    pub metadata_app: Option<String>,
    #[serde(default)]
    pub plan_code_prefix: Option<String>,
    #[serde(default)]
    pub reference_prefix: Option<String>,
    #[serde(alias = "app_id")]
    pub app_identifier: Option<String>,
    pub environment: Option<String>,
}

const EXTENDED_MATCHER_PREFIX: &str = "__fanout_extended_matcher__:";

impl RouteMatcher {
    pub fn extended(&self) -> ExtendedRouteMatcher {
        let Some(encoded) = self
            .metadata_app
            .as_deref()
            .and_then(|value| value.strip_prefix(EXTENDED_MATCHER_PREFIX))
        else {
            return ExtendedRouteMatcher {
                metadata_app: self.metadata_app.clone(),
                plan_code_prefix: self.plan_code_prefix.clone(),
                reference_prefix: self.reference_prefix.clone(),
                ..ExtendedRouteMatcher::default()
            };
        };
        let mut matcher: ExtendedRouteMatcher = serde_json::from_str(encoded).unwrap_or_default();
        matcher.plan_code_prefix = self.plan_code_prefix.clone();
        matcher.reference_prefix = self.reference_prefix.clone();
        matcher
    }

    pub fn from_extended(matcher: ExtendedRouteMatcher) -> Self {
        let ExtendedRouteMatcher {
            metadata_app,
            plan_code_prefix,
            reference_prefix,
            app_identifier,
            environment,
        } = matcher;
        let metadata_app = if app_identifier.is_some() || environment.is_some() {
            let encoded = serde_json::to_string(&ExtendedRouteMatcher {
                metadata_app,
                plan_code_prefix: None,
                reference_prefix: None,
                app_identifier,
                environment,
            })
            .unwrap_or_default();
            Some(format!("{EXTENDED_MATCHER_PREFIX}{encoded}"))
        } else {
            metadata_app
        };
        Self {
            metadata_app,
            plan_code_prefix,
            reference_prefix,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RouteMatcherWire {
    #[serde(default)]
    metadata_app: Option<String>,
    #[serde(default)]
    plan_code_prefix: Option<String>,
    #[serde(default)]
    reference_prefix: Option<String>,
    #[serde(alias = "app_id")]
    app_identifier: Option<String>,
    environment: Option<String>,
}

impl<'de> Deserialize<'de> for RouteMatcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RouteMatcherWire::deserialize(deserializer)?;
        Ok(Self::from_extended(ExtendedRouteMatcher {
            metadata_app: wire.metadata_app,
            plan_code_prefix: wire.plan_code_prefix,
            reference_prefix: wire.reference_prefix,
            app_identifier: wire.app_identifier,
            environment: wire.environment,
        }))
    }
}

impl Serialize for RouteMatcher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.extended().serialize(serializer)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FallbackConfig {
    pub mode: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertsConfig {
    pub webhook_url_env: String,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let text = match path {
            None => {
                tracing::info!("no config file was found and routes come from the database");
                return Self::defaults();
            }
            Some(path) => match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tracing::info!("no config file was found and routes come from the database");
                    return Self::defaults();
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("reading config {}", path.display()));
                }
            },
        };
        let mut config: Self = toml::from_str(&text).context("parsing TOML config")?;
        config.apply_retention_override()?;
        config.validate()?;
        Ok(config)
    }

    fn defaults() -> Result<Self> {
        let mut config = Self {
            source: HashMap::from([(
                "paystack_main".to_owned(),
                SourceConfig {
                    provider: "paystack".to_owned(),
                    secret_env: "PAYSTACK_SECRET_KEY".to_owned(),
                    allowed_ips: Vec::new(),
                },
            )]),
            route: Vec::new(),
            fallback: FallbackConfig {
                mode: "unrouted".to_owned(),
            },
            alerts: None,
            retention_days: default_retention_days(),
        };
        config.apply_retention_override()?;
        config.validate()?;
        Ok(config)
    }

    fn apply_retention_override(&mut self) -> Result<()> {
        if let Ok(value) = env::var("RETENTION_DAYS") {
            self.retention_days = value.parse().context("parsing RETENTION_DAYS")?;
        }
        Ok(())
    }

    pub fn secret_for(&self, source: &str) -> Result<String> {
        let source_config = self.source.get(source).context("unknown source")?;
        env::var(&source_config.secret_env)
            .with_context(|| format!("missing secret env {}", source_config.secret_env))
    }

    pub fn alert_url(&self) -> Option<String> {
        self.alerts
            .as_ref()
            .and_then(|a| env::var(&a.webhook_url_env).ok())
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.source.is_empty(), "at least one source is required");
        let mut names = std::collections::HashSet::new();
        for route in &self.route {
            anyhow::ensure!(names.insert(&route.name), "duplicate route {}", route.name);
            anyhow::ensure!(
                route.destination_url.starts_with("https://")
                    || route.destination_url.starts_with("http://"),
                "route {} must use http(s)",
                route.name
            );
        }
        anyhow::ensure!(
            self.fallback.mode == "unrouted"
                || self
                    .fallback
                    .mode
                    .strip_prefix("route:")
                    .is_some_and(|name| names.contains(&name.to_string())),
            "fallback must be unrouted or route:<configured route>"
        );
        for source in self.source.values() {
            anyhow::ensure!(
                crate::provider::supported_providers().contains(&source.provider.as_str()),
                "unsupported provider {}",
                source.provider
            );
        }
        for route in &self.route {
            if let Some(environment) = route.matcher.extended().environment.as_deref() {
                anyhow::ensure!(
                    matches!(environment, "production" | "sandbox"),
                    "route {} environment must be production or sandbox",
                    route.name
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn missing_config_uses_database_managed_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::load(Some(&directory.path().join("missing.toml"))).unwrap();
        assert_eq!(config.source.len(), 1);
        let source = config.source.get("paystack_main").unwrap();
        assert_eq!(source.provider, "paystack");
        assert_eq!(source.secret_env, "PAYSTACK_SECRET_KEY");
        assert!(config.route.is_empty());
        assert_eq!(config.fallback.mode, "unrouted");
        assert_eq!(config.retention_days, 90);
    }

    #[test]
    fn store_sources_and_matchers_are_valid_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[source.apple]
provider = "apple_server_notifications"
secret_env = "APPLE_SECRET"

[[route]]
name = "store"
destination_url = "https://example.invalid/store"
match = { app_identifier = "com.example.store", environment = "sandbox" }

[fallback]
mode = "unrouted"
"#,
        )
        .unwrap();
        let config = Config::load(Some(&path)).unwrap();
        assert_eq!(
            config.source["apple"].provider,
            "apple_server_notifications"
        );
        let matcher = config.route[0].matcher.extended();
        assert_eq!(matcher.app_identifier.as_deref(), Some("com.example.store"));
        assert_eq!(matcher.environment.as_deref(), Some("sandbox"));
    }
}
