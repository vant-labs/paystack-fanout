use std::{collections::HashMap, env, net::IpAddr, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

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

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
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
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut config: Self = toml::from_str(&text).context("parsing TOML config")?;
        if let Ok(value) = env::var("RETENTION_DAYS") {
            config.retention_days = value.parse().context("parsing RETENTION_DAYS")?;
        }
        config.validate()?;
        Ok(config)
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
        anyhow::ensure!(!self.route.is_empty(), "at least one route is required");
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
