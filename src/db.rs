use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures_util::Stream;
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::auth::{Role, SessionUser, token_hash};
use crate::config::{Config, RouteConfig, RouteMatcher, SourceConfig};
use crate::crypto::{decrypt, encrypt};

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

#[derive(Debug)]
pub struct ClaimedDelivery {
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub attempt: i32,
    pub raw_body: Vec<u8>,
    pub content_type: String,
    pub signature: String,
    pub destination_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventSummary {
    pub id: Uuid,
    pub source: String,
    pub event_type: String,
    pub matched_route: Option<String>,
    pub status: String,
    pub received_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttemptView {
    pub attempt: i32,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status_code: Option<i32>,
    pub latency_ms: i32,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventDetail {
    pub summary: EventSummary,
    pub raw_body: String,
    pub headers: Value,
    pub routing_reason: Option<String>,
    pub attempts: Vec<AttemptView>,
}

#[derive(Debug)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: Role,
    pub disabled: bool,
    pub totp_secret: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserView {
    pub id: Uuid,
    pub email: String,
    pub role: Role,
    pub disabled: bool,
    pub totp_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_label: String,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub metadata: Value,
    pub remote_addr: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct OverviewStats {
    pub received_24h: i64,
    pub received_7d: i64,
    pub delivered_24h: i64,
    pub retrying: i64,
    pub dead: i64,
    pub unrouted: i64,
    pub total_with_delivery: i64,
    pub delivered_with_delivery: i64,
}

#[derive(Debug, Clone)]
pub struct SourceView {
    pub name: String,
    pub provider: String,
    pub allowed_ips: Vec<String>,
    pub enabled: bool,
    pub secret_present: bool,
}

#[derive(Debug, Clone)]
pub struct RouteView {
    pub name: String,
    pub destination_url: String,
    pub matcher: RouteMatcher,
    pub timeout_seconds: i32,
    pub max_attempts: i32,
    pub enabled: bool,
}

impl Database {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
            .context("connecting to postgres")?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .context("running migrations")?;
        Ok(())
    }

    pub async fn seed_runtime_config(&self, config: &Config) -> Result<()> {
        let source_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sources")
            .fetch_one(&self.pool)
            .await?;
        let route_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM routes")
            .fetch_one(&self.pool)
            .await?;
        let mut tx = self.pool.begin().await?;
        if source_count == 0 {
            for (name, source) in &config.source {
                let secret = config.secret_for(name)?;
                sqlx::query("INSERT INTO sources (id, name, provider, secret_ciphertext, allowed_ips, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, now(), now())")
                    .bind(Uuid::new_v4())
                    .bind(name)
                    .bind(&source.provider)
                    .bind(encrypt(&secret)?)
                    .bind(serde_json::to_value(&source.allowed_ips)?)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        if route_count == 0 {
            for route in &config.route {
                sqlx::query("INSERT INTO routes (id, name, destination_url, matcher, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())")
                    .bind(Uuid::new_v4())
                    .bind(&route.name)
                    .bind(&route.destination_url)
                    .bind(serde_json::to_value(&route.matcher)?)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn load_runtime_config(
        &self,
        base: &Config,
    ) -> (Config, std::collections::HashMap<String, String>) {
        let mut config = base.clone();
        let mut secrets = std::collections::HashMap::new();
        let source_rows = sqlx::query("SELECT name, provider, secret_ciphertext, allowed_ips FROM sources WHERE enabled = true ORDER BY name")
            .fetch_all(&self.pool)
            .await;
        if let Ok(rows) = source_rows
            && !rows.is_empty()
        {
            config.source.clear();
            for row in rows {
                let name: String = match row.try_get("name") {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let provider: String = match row.try_get("provider") {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let ciphertext: String = match row.try_get("secret_ciphertext") {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let allowed_ips = row
                    .try_get("allowed_ips")
                    .ok()
                    .and_then(|value: Value| serde_json::from_value(value).ok())
                    .unwrap_or_default();
                if let Ok(secret) = decrypt(&ciphertext) {
                    secrets.insert(name.clone(), secret);
                }
                config.source.insert(
                    name,
                    SourceConfig {
                        provider,
                        secret_env: "FANOUT_DB_SECRET".to_owned(),
                        allowed_ips,
                    },
                );
            }
        }
        let route_rows = sqlx::query(
            "SELECT name, destination_url, matcher FROM routes WHERE enabled = true ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await;
        if let Ok(rows) = route_rows
            && !rows.is_empty()
        {
            config.route = rows
                .into_iter()
                .filter_map(|row| {
                    let name: String = row.try_get("name").ok()?;
                    let destination_url: String = row.try_get("destination_url").ok()?;
                    let matcher: Value = row.try_get("matcher").ok()?;
                    let matcher: RouteMatcher = serde_json::from_value(matcher).ok()?;
                    Some(RouteConfig {
                        name,
                        destination_url,
                        matcher,
                    })
                })
                .collect();
        }
        if let Ok(rows) = sqlx::query("SELECT key, value FROM settings")
            .fetch_all(&self.pool)
            .await
        {
            for row in rows {
                let key: String = match row.try_get("key") {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let value: Value = match row.try_get("value") {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                match key.as_str() {
                    "retention_days" => {
                        if let Some(days) = value.as_u64().and_then(|days| u32::try_from(days).ok())
                        {
                            config.retention_days = days;
                        }
                    }
                    "fallback_mode" => {
                        if let Some(mode) = value.as_str() {
                            config.fallback = crate::config::FallbackConfig {
                                mode: mode.to_owned(),
                            };
                        }
                    }
                    _ => {}
                }
            }
        }
        (config, secrets)
    }

    pub async fn alert_url_setting(&self) -> Option<String> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'alert_webhook_url'")
            .fetch_optional(&self.pool)
            .await
            .ok()??;
        let value: Value = row.try_get("value").ok()?;
        decrypt(value.as_str()?).ok()
    }

    pub async fn save_settings(
        &self,
        retention_days: u32,
        fallback_mode: &str,
        alert_url: Option<&str>,
    ) -> Result<()> {
        anyhow::ensure!(
            (1..=3_650).contains(&retention_days),
            "retention must be between 1 and 3650 days"
        );
        anyhow::ensure!(
            fallback_mode == "unrouted" || fallback_mode.starts_with("route:"),
            "invalid fallback mode"
        );
        for (key, value) in [
            ("retention_days", serde_json::json!(retention_days)),
            ("fallback_mode", serde_json::json!(fallback_mode)),
        ] {
            sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()")
                .bind(key)
                .bind(value)
                .execute(&self.pool)
                .await?;
        }
        if let Some(alert_url) = alert_url.filter(|value| !value.trim().is_empty()) {
            sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES ('alert_webhook_url', $1, now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()")
                .bind(serde_json::json!(encrypt(alert_url)?))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn list_sources(&self) -> Result<Vec<SourceView>> {
        let rows = sqlx::query("SELECT name, provider, allowed_ips, enabled, secret_ciphertext <> '' AS secret_present FROM sources ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let allowed: Value = row.try_get("allowed_ips")?;
                Ok(SourceView {
                    name: row.try_get("name")?,
                    provider: row.try_get("provider")?,
                    allowed_ips: serde_json::from_value::<Vec<String>>(allowed).unwrap_or_default(),
                    enabled: row.try_get("enabled")?,
                    secret_present: row.try_get("secret_present")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    pub async fn list_routes(&self) -> Result<Vec<RouteView>> {
        let rows = sqlx::query("SELECT name, destination_url, matcher, timeout_seconds, max_attempts, enabled FROM routes ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let matcher: Value = row.try_get("matcher")?;
                Ok(RouteView {
                    name: row.try_get("name")?,
                    destination_url: row.try_get("destination_url")?,
                    matcher: serde_json::from_value(matcher).unwrap_or_default(),
                    timeout_seconds: row.try_get("timeout_seconds")?,
                    max_attempts: row.try_get("max_attempts")?,
                    enabled: row.try_get("enabled")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    pub async fn save_route(
        &self,
        name: &str,
        destination_url: &str,
        matcher: &RouteMatcher,
        timeout_seconds: i32,
        max_attempts: i32,
        enabled: bool,
    ) -> Result<()> {
        sqlx::query("INSERT INTO routes (id, name, destination_url, matcher, timeout_seconds, max_attempts, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now()) ON CONFLICT (name) DO UPDATE SET destination_url = EXCLUDED.destination_url, matcher = EXCLUDED.matcher, timeout_seconds = EXCLUDED.timeout_seconds, max_attempts = EXCLUDED.max_attempts, enabled = EXCLUDED.enabled, updated_at = now()")
            .bind(Uuid::new_v4())
            .bind(name)
            .bind(destination_url)
            .bind(serde_json::to_value(matcher)?)
            .bind(timeout_seconds)
            .bind(max_attempts)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn save_source(
        &self,
        name: &str,
        provider: &str,
        secret: Option<&str>,
        allowed_ips: &[String],
        enabled: bool,
    ) -> Result<()> {
        let ciphertext = secret.map(encrypt).transpose()?;
        sqlx::query("INSERT INTO sources (id, name, provider, secret_ciphertext, allowed_ips, enabled, created_at, updated_at) VALUES ($1, $2, $3, COALESCE($4, ''), $5, $6, now(), now()) ON CONFLICT (name) DO UPDATE SET provider = EXCLUDED.provider, secret_ciphertext = CASE WHEN $4 IS NULL THEN sources.secret_ciphertext ELSE EXCLUDED.secret_ciphertext END, allowed_ips = EXCLUDED.allowed_ips, enabled = EXCLUDED.enabled, updated_at = now()")
            .bind(Uuid::new_v4())
            .bind(name)
            .bind(provider)
            .bind(ciphertext)
            .bind(serde_json::to_value(allowed_ips)?)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn user_count(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn create_owner(&self, email: &str, password_hash: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, password_hash, role, created_at) VALUES ($1, $2, $3, 'owner', now())")
            .bind(id)
            .bind(email.trim().to_ascii_lowercase())
            .bind(password_hash)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>> {
        let row = sqlx::query("SELECT id, email, password_hash, role, disabled, totp_secret FROM users WHERE lower(email) = lower($1)")
            .bind(email.trim())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| -> Result<UserRecord, sqlx::Error> {
            Ok(UserRecord {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
                password_hash: row.try_get("password_hash")?,
                role: Role::parse(row.try_get::<String, _>("role")?.as_str())
                    .ok_or_else(|| sqlx::Error::Protocol("invalid user role".into()))?,
                disabled: row.try_get("disabled")?,
                totp_secret: row.try_get("totp_secret")?,
            })
        })
        .transpose()
        .map_err(Into::into)
    }

    pub async fn mark_login(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<UserView>> {
        let rows = sqlx::query("SELECT id, email, role, disabled, totp_secret IS NOT NULL AS totp_enabled, last_login_at FROM users ORDER BY lower(email)")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let role = Role::parse(row.try_get::<String, _>("role")?.as_str())
                    .ok_or_else(|| sqlx::Error::Protocol("invalid user role".into()))?;
                let last_login_at: Option<DateTime<Utc>> = row.try_get("last_login_at")?;
                Ok(UserView {
                    id: row.try_get("id")?,
                    email: row.try_get("email")?,
                    role,
                    disabled: row.try_get("disabled")?,
                    totp_enabled: row.try_get("totp_enabled")?,
                    last_login_label: last_login_at
                        .map(|value| value.to_rfc3339())
                        .unwrap_or_else(|| "Never".to_owned()),
                    last_login_at,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    pub async fn create_user(&self, email: &str, password_hash: &str, role: Role) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, password_hash, role, created_at) VALUES ($1, $2, $3, $4, now())")
            .bind(id)
            .bind(email.trim().to_ascii_lowercase())
            .bind(password_hash)
            .bind(role.to_string())
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    pub async fn set_user_disabled(&self, id: Uuid, disabled: bool) -> Result<bool> {
        let result = sqlx::query("UPDATE users SET disabled = $2 WHERE id = $1")
            .bind(id)
            .bind(disabled)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn reset_totp(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("UPDATE users SET totp_secret = NULL WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn create_session(&self, user_id: Uuid, token: &str, csrf_token: &str) -> Result<()> {
        sqlx::query("INSERT INTO sessions (id, token_hash, user_id, csrf_token, created_at, expires_at, last_seen_at) VALUES ($1, $2, $3, $4, now(), now() + interval '14 days', now())")
            .bind(Uuid::new_v4())
            .bind(token_hash(token))
            .bind(user_id)
            .bind(csrf_token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn session_user(&self, token: &str) -> Result<Option<SessionUser>> {
        let row = sqlx::query("SELECT s.user_id, u.email, u.role, s.csrf_token FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now() AND u.disabled = false")
            .bind(token_hash(token))
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| -> Result<SessionUser, sqlx::Error> {
            Ok(SessionUser {
                id: row.try_get("user_id")?,
                email: row.try_get("email")?,
                initial: row
                    .try_get::<String, _>("email")?
                    .chars()
                    .next()
                    .unwrap_or('?')
                    .to_ascii_uppercase()
                    .to_string(),
                role: Role::parse(row.try_get::<String, _>("role")?.as_str())
                    .ok_or_else(|| sqlx::Error::Protocol("invalid user role".into()))?,
                can_write: Role::parse(row.try_get::<String, _>("role")?.as_str())
                    .is_some_and(Role::can_write),
                can_manage: Role::parse(row.try_get::<String, _>("role")?.as_str())
                    .is_some_and(Role::can_manage),
                csrf_token: row.try_get("csrf_token")?,
                session_token: token.to_owned(),
            })
        })
        .transpose()
        .map_err(Into::into)
    }

    pub async fn touch_session(&self, token: &str) -> Result<()> {
        sqlx::query("UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1")
            .bind(token_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn audit(
        &self,
        user_id: Option<Uuid>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<&str>,
        metadata: &Value,
        remote_addr: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO audit_logs (user_id, action, target_type, target_id, metadata, remote_addr, created_at) VALUES ($1, $2, $3, $4, $5, $6, now())")
            .bind(user_id)
            .bind(action)
            .bind(target_type)
            .bind(target_id)
            .bind(metadata)
            .bind(remote_addr)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_audit(&self, limit: i64, offset: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query("SELECT id, action, target_type, target_id, metadata, remote_addr, created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2")
            .bind(limit.clamp(1, 100))
            .bind(offset.max(0))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    id: row.try_get("id")?,
                    action: row.try_get("action")?,
                    target_type: row.try_get("target_type")?,
                    target_id: row.try_get("target_id")?,
                    metadata: row.try_get("metadata")?,
                    remote_addr: row.try_get("remote_addr")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    pub async fn overview_stats(&self) -> Result<OverviewStats> {
        let row = sqlx::query("SELECT COUNT(*) FILTER (WHERE received_at >= now() - interval '24 hours') AS received_24h, COUNT(*) FILTER (WHERE received_at >= now() - interval '7 days') AS received_7d, COUNT(*) FILTER (WHERE status = 'delivered' AND received_at >= now() - interval '24 hours') AS delivered_24h, COUNT(*) FILTER (WHERE status = 'retrying') AS retrying, COUNT(*) FILTER (WHERE status = 'dead') AS dead, COUNT(*) FILTER (WHERE status = 'unrouted') AS unrouted FROM events")
            .fetch_one(&self.pool)
            .await?;
        let delivery_row = sqlx::query("SELECT COUNT(*) AS total_with_delivery, COUNT(*) FILTER (WHERE status = 'delivered') AS delivered_with_delivery FROM deliveries")
            .fetch_one(&self.pool)
            .await?;
        Ok(OverviewStats {
            received_24h: row.try_get("received_24h")?,
            received_7d: row.try_get("received_7d")?,
            delivered_24h: row.try_get("delivered_24h")?,
            retrying: row.try_get("retrying")?,
            dead: row.try_get("dead")?,
            unrouted: row.try_get("unrouted")?,
            total_with_delivery: delivery_row.try_get("total_with_delivery")?,
            delivered_with_delivery: delivery_row.try_get("delivered_with_delivery")?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_event(
        &self,
        source: &str,
        event_type: &str,
        raw_body: &[u8],
        content_type: &str,
        signature: &str,
        headers: &Value,
        dedupe_key: &str,
        matched_route: Option<&str>,
        routing_reason: Option<&str>,
        status: &str,
        destination_url: Option<&str>,
    ) -> Result<InsertResult> {
        let event_id = Uuid::new_v4();
        let delivery_id = Uuid::new_v4();
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            r#"INSERT INTO events (id, source, event_type, raw_body, content_type, signature, headers, dedupe_key, matched_route, routing_reason, status, received_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (source, dedupe_key) DO NOTHING"#,
        )
        .bind(event_id)
        .bind(source)
        .bind(event_type)
        .bind(raw_body)
        .bind(content_type)
        .bind(signature)
        .bind(headers)
        .bind(dedupe_key)
        .bind(matched_route)
        .bind(routing_reason)
        .bind(status)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(InsertResult::Duplicate);
        }
        if let Some(destination_url) = destination_url {
            sqlx::query!(
                r#"INSERT INTO deliveries (id, event_id, destination_url, status, attempts, next_attempt_at, created_at)
                   VALUES ($1, $2, $3, 'pending', 0, $4, $4)"#,
                delivery_id,
                event_id,
                destination_url,
                now,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(InsertResult::Inserted { event_id })
    }

    pub async fn claim_delivery(&self) -> Result<Option<ClaimedDelivery>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query!(
            r#"SELECT d.id as delivery_id, d.event_id, d.attempts, e.raw_body, e.content_type, e.signature, d.destination_url
               FROM deliveries d JOIN events e ON e.id = d.event_id
               WHERE ((d.status IN ('pending', 'retrying') AND d.next_attempt_at <= now())
                  OR (d.status = 'delivering' AND d.locked_at < now() - interval '2 minutes'))
               ORDER BY d.next_attempt_at ASC FOR UPDATE OF d SKIP LOCKED LIMIT 1"#
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let attempt = row.attempts + 1;
        sqlx::query!(
            "UPDATE deliveries SET status = 'delivering', attempts = $2, locked_at = now() WHERE id = $1",
            row.delivery_id,
            attempt,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(ClaimedDelivery {
            delivery_id: row.delivery_id,
            event_id: row.event_id,
            attempt,
            raw_body: row.raw_body,
            content_type: row.content_type,
            signature: row.signature,
            destination_url: row.destination_url,
        }))
    }

    pub async fn record_success(
        &self,
        delivery: &ClaimedDelivery,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        status_code: u16,
        response_body: Option<&str>,
        latency_ms: i32,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"INSERT INTO delivery_attempts (delivery_id, attempt, started_at, finished_at, status_code, latency_ms, response_body)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            delivery.delivery_id, delivery.attempt, started_at, finished_at, i32::from(status_code), latency_ms, response_body,
        ).execute(&mut *tx).await?;
        sqlx::query!("UPDATE deliveries SET status = 'delivered', delivered_at = $2, locked_at = NULL WHERE id = $1", delivery.delivery_id, finished_at).execute(&mut *tx).await?;
        sqlx::query!(
            "UPDATE events SET status = 'delivered', delivered_at = $2 WHERE id = $1",
            delivery.event_id,
            finished_at
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_failure(
        &self,
        delivery: &ClaimedDelivery,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        status_code: Option<u16>,
        response_body: Option<&str>,
        error: Option<&str>,
        latency_ms: i32,
        next: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"INSERT INTO delivery_attempts (delivery_id, attempt, started_at, finished_at, status_code, latency_ms, response_body, error)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
            delivery.delivery_id, delivery.attempt, started_at, finished_at, status_code.map(i32::from), latency_ms, response_body, error,
        ).execute(&mut *tx).await?;
        let (status, event_status) = if next.is_some() {
            ("retrying", "retrying")
        } else {
            ("dead", "dead")
        };
        sqlx::query!("UPDATE deliveries SET status = $2, next_attempt_at = COALESCE($3, next_attempt_at), locked_at = NULL WHERE id = $1", delivery.delivery_id, status, next).execute(&mut *tx).await?;
        sqlx::query!(
            "UPDATE events SET status = $2 WHERE id = $1",
            delivery.event_id,
            event_status
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_events(
        &self,
        status: Option<&str>,
        route: Option<&str>,
        event_type: Option<&str>,
        since: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<EventSummary>> {
        let rows = sqlx::query(
            r"SELECT id, source, event_type, matched_route, status, received_at, delivered_at FROM events
               WHERE ($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR matched_route = $2)
                 AND ($3::text IS NULL OR event_type = $3) AND ($4::timestamptz IS NULL OR received_at >= $4)
               ORDER BY received_at DESC LIMIT $5 OFFSET $6",
        )
        .bind(status).bind(route).bind(event_type).bind(since).bind(limit).bind(offset)
        .fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(EventSummary {
                    id: row.try_get("id")?,
                    source: row.try_get("source")?,
                    event_type: row.try_get("event_type")?,
                    matched_route: row.try_get("matched_route")?,
                    status: row.try_get("status")?,
                    received_at: row.try_get("received_at")?,
                    delivered_at: row.try_get("delivered_at")?,
                })
            })
            .collect()
    }

    pub async fn get_event(&self, event_id: Uuid) -> Result<Option<EventDetail>> {
        let Some(row) = sqlx::query("SELECT id, source, event_type, raw_body, headers, routing_reason, matched_route, status, received_at, delivered_at FROM events WHERE id = $1").bind(event_id).fetch_optional(&self.pool).await? else { return Ok(None) };
        let summary = EventSummary {
            id: row.try_get("id")?,
            source: row.try_get("source")?,
            event_type: row.try_get("event_type")?,
            matched_route: row.try_get("matched_route")?,
            status: row.try_get("status")?,
            received_at: row.try_get("received_at")?,
            delivered_at: row.try_get("delivered_at")?,
        };
        let raw_body: Vec<u8> = row.try_get("raw_body")?;
        let headers: Value = row.try_get("headers")?;
        let routing_reason: Option<String> = row.try_get("routing_reason")?;
        let rows = sqlx::query("SELECT da.attempt, da.started_at, da.finished_at, da.status_code, da.latency_ms, da.response_body, da.error FROM delivery_attempts da JOIN deliveries d ON d.id = da.delivery_id WHERE d.event_id = $1 ORDER BY da.attempt").bind(event_id).fetch_all(&self.pool).await?;
        let attempts = rows
            .into_iter()
            .map(|row| {
                Ok(AttemptView {
                    attempt: row.try_get("attempt")?,
                    started_at: row.try_get("started_at")?,
                    finished_at: row.try_get("finished_at")?,
                    status_code: row.try_get("status_code")?,
                    latency_ms: row.try_get("latency_ms")?,
                    response_body: row.try_get("response_body")?,
                    error: row.try_get("error")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        Ok(Some(EventDetail {
            summary,
            raw_body: String::from_utf8_lossy(&raw_body).into_owned(),
            headers,
            routing_reason,
            attempts,
        }))
    }

    pub async fn replay(
        &self,
        event_id: Uuid,
        route: Option<&str>,
        config: &Config,
    ) -> Result<bool> {
        let destination = if let Some(route) = route {
            config
                .route
                .iter()
                .find(|r| r.name == route)
                .map(|r| r.destination_url.clone())
        } else {
            None
        };
        let mut tx = self.pool.begin().await?;
        let Some(row) =
            sqlx::query("SELECT matched_route, status FROM events WHERE id = $1 FOR UPDATE")
                .bind(event_id)
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Ok(false);
        };
        let existing_route: Option<String> = row.try_get("matched_route")?;
        let destination = destination.or_else(|| {
            existing_route.as_deref().and_then(|name| {
                config
                    .route
                    .iter()
                    .find(|r| r.name == name)
                    .map(|r| r.destination_url.clone())
            })
        });
        let Some(destination) = destination else {
            return Ok(false);
        };
        let now = Utc::now();
        sqlx::query("DELETE FROM deliveries WHERE event_id = $1")
            .bind(event_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO deliveries (id, event_id, destination_url, status, attempts, next_attempt_at, created_at) VALUES ($1, $2, $3, 'pending', 0, $4, $4)").bind(Uuid::new_v4()).bind(event_id).bind(destination).bind(now).execute(&mut *tx).await?;
        sqlx::query("UPDATE events SET status = 'pending', matched_route = COALESCE($2, matched_route), delivered_at = NULL WHERE id = $1").bind(event_id).bind(route).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn bulk_replay(&self, status: &str, route: &str, config: &Config) -> Result<u64> {
        let ids = sqlx::query("SELECT id FROM events WHERE status = $1 AND matched_route = $2")
            .bind(status)
            .bind(route)
            .fetch_all(&self.pool)
            .await?;
        let mut count = 0;
        for id in ids {
            let event_id: Uuid = id.try_get("id")?;
            if self.replay(event_id, Some(route), config).await? {
                count += 1;
            }
        }
        Ok(count)
    }

    pub async fn retry_now(&self, event_id: Uuid) -> Result<bool> {
        let result = sqlx::query("UPDATE deliveries SET status = 'pending', next_attempt_at = now(), locked_at = NULL WHERE event_id = $1 AND status IN ('retrying', 'dead')")
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query("UPDATE events SET status = 'pending', delivered_at = NULL WHERE id = $1")
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }

    pub async fn move_to_dead(&self, event_id: Uuid) -> Result<bool> {
        let result = sqlx::query("UPDATE deliveries SET status = 'dead', locked_at = NULL WHERE event_id = $1 AND status IN ('pending', 'retrying')")
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query("UPDATE events SET status = 'dead' WHERE id = $1")
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }

    pub fn export_events(
        self,
        status: Option<String>,
        route: Option<String>,
        event_type: Option<String>,
        source: Option<String>,
    ) -> impl Stream<Item = std::result::Result<sqlx::postgres::PgRow, sqlx::Error>> + 'static {
        sqlx::query("SELECT id, source, event_type, matched_route, status, received_at, delivered_at, raw_body FROM events WHERE ($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR matched_route = $2) AND ($3::text IS NULL OR event_type = $3) AND ($4::text IS NULL OR source = $4) ORDER BY received_at DESC")
            .bind(status)
            .bind(route)
            .bind(event_type)
            .bind(source)
            .fetch(&self.pool)
    }

    pub async fn prune_delivered(&self, retention_days: u32) -> Result<u64> {
        let result = sqlx::query("DELETE FROM events WHERE status = 'delivered' AND delivered_at < now() - make_interval(days => $1)").bind(i32::try_from(retention_days)?).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
}

pub enum InsertResult {
    Inserted { event_id: Uuid },
    Duplicate,
}
