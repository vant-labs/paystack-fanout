use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::config::Config;

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

#[derive(Debug, Serialize)]
pub struct EventSummary {
    pub id: Uuid,
    pub source: String,
    pub event_type: String,
    pub matched_route: Option<String>,
    pub status: String,
    pub received_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AttemptView {
    pub attempt: i32,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status_code: Option<i32>,
    pub latency_ms: i32,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EventDetail {
    pub summary: EventSummary,
    pub attempts: Vec<AttemptView>,
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
        status: &str,
        destination_url: Option<&str>,
    ) -> Result<InsertResult> {
        let event_id = Uuid::new_v4();
        let delivery_id = Uuid::new_v4();
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query!(
            r#"INSERT INTO events (id, source, event_type, raw_body, content_type, signature, headers, dedupe_key, matched_route, status, received_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (source, dedupe_key) DO NOTHING"#,
            event_id,
            source,
            event_type,
            raw_body,
            content_type,
            signature,
            headers,
            dedupe_key,
            matched_route,
            status,
            now,
        )
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
        let Some(row) = sqlx::query("SELECT id, source, event_type, matched_route, status, received_at, delivered_at FROM events WHERE id = $1").bind(event_id).fetch_optional(&self.pool).await? else { return Ok(None) };
        let summary = EventSummary {
            id: row.try_get("id")?,
            source: row.try_get("source")?,
            event_type: row.try_get("event_type")?,
            matched_route: row.try_get("matched_route")?,
            status: row.try_get("status")?,
            received_at: row.try_get("received_at")?,
            delivered_at: row.try_get("delivered_at")?,
        };
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
        Ok(Some(EventDetail { summary, attempts }))
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

    pub async fn prune_delivered(&self, retention_days: u32) -> Result<u64> {
        let result = sqlx::query("DELETE FROM events WHERE status = 'delivered' AND delivered_at < now() - make_interval(days => $1)").bind(i32::try_from(retention_days)?).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
}

pub enum InsertResult {
    Inserted { event_id: Uuid },
    Duplicate,
}
