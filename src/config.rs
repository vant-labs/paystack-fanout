use std::{collections::HashMap, env, net::IpAddr, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RouteMatcher {
    pub metadata_app: Option<String>,
    pub plan_code_prefix: Option<String>,
    pub reference_prefix: Option<String>,
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
                source.provider == "paystack",
                "only paystack is implemented"
            );
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
}
