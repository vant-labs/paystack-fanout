use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::{Duration, sleep};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    config::Config,
    db::{Database, InsertResult},
    metrics::Metrics,
    provider::{PaystackProvider, Provider},
    routing::{MatchSource, decide},
    security::{bearer_matches, dedupe_key},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub metrics: Arc<Metrics>,
    pub http: reqwest::Client,
    pub trust_proxy: bool,
    pub admin_token: Option<String>,
    pub cookie_secure: bool,
    pub login_limits: Arc<std::sync::Mutex<HashMap<String, (u32, Instant)>>>,
    pub runtime_config: Arc<tokio::sync::RwLock<Config>>,
    pub runtime_secrets: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    pub runtime_alert_url: Arc<tokio::sync::RwLock<Option<String>>>,
    alert_url_override: Option<String>,
}

impl AppState {
    pub fn new(config: Config, db: Database) -> anyhow::Result<Self> {
        Self::new_with_alert_url(config, db, None)
    }

    pub fn new_with_alert_url(
        config: Config,
        db: Database,
        alert_url_override: Option<String>,
    ) -> anyhow::Result<Self> {
        let runtime_config = config.clone();
        Ok(Self {
            config,
            db,
            metrics: Arc::new(Metrics::default()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            trust_proxy: std::env::var("TRUST_PROXY")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
            admin_token: std::env::var("ADMIN_TOKEN").ok(),
            cookie_secure: std::env::var("COOKIE_SECURE")
                .map(|value| !value.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            login_limits: Arc::new(std::sync::Mutex::new(HashMap::new())),
            runtime_config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
            runtime_secrets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            runtime_alert_url: Arc::new(tokio::sync::RwLock::new(None)),
            alert_url_override,
        })
    }

    pub async fn reload_runtime_config(&self) -> anyhow::Result<()> {
        let (config, secrets) = self.db.load_runtime_config(&self.config).await;
        *self.runtime_config.write().await = config;
        *self.runtime_secrets.write().await = secrets;
        *self.runtime_alert_url.write().await = self.db.alert_url_setting().await;
        Ok(())
    }

    pub async fn alert(&self, text: String) {
        let Some(url) = self
            .alert_url_override
            .clone()
            .or_else(|| {
                self.runtime_alert_url
                    .try_read()
                    .ok()
                    .and_then(|value| value.clone())
            })
            .or_else(|| self.config.alert_url())
        else {
            return;
        };
        let result = self
            .http
            .post(url)
            .json(&json!({"text": text}))
            .send()
            .await;
        if let Err(error) = result {
            tracing::warn!(error = %error, "alert delivery failed");
        }
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(crate::dashboard::router())
        .merge(
            SwaggerUi::new("/docs")
                .url("/api-docs/openapi.json", crate::openapi::ApiDoc::openapi()),
        )
        .route("/in/{source}", post(ingest))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/admin/events", get(list_events))
        .route("/admin/events/{id}", get(get_event).post(replay_event))
        .route("/admin/replay", post(bulk_replay))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/in/{source}",
    params(("source" = String, Path, description = "Configured source name")),
    request_body(content_type = "application/json", content = Value),
    responses(
        (status = 200, description = "Webhook accepted for durable processing"),
        (status = 400, description = "Verified body was not valid JSON"),
        (status = 401, description = "Signature verification failed"),
        (status = 403, description = "Source IP is not allowed"),
        (status = 404, description = "Source was not found")
    ),
    tag = "Webhook"
)]
pub(crate) async fn ingest(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
    headers: HeaderMap,
    remote: ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    let active_config = state.runtime_config.read().await.clone();
    let active_secrets = state.runtime_secrets.read().await.clone();
    let Some(source_config) = active_config.source.get(&source) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !allowed_ip(
        source_config.allowed_ips.as_slice(),
        state.trust_proxy,
        &headers,
        Some(remote.0.ip()),
    ) {
        tracing::warn!(source = %source, "webhook rejected by IP allowlist");
        return StatusCode::FORBIDDEN.into_response();
    }
    let signature = headers
        .get("x-paystack-signature")
        .and_then(|value| value.to_str().ok());
    let secret = match active_secrets
        .get(&source)
        .cloned()
        .or_else(|| active_config.secret_for(&source).ok())
    {
        Some(secret) => secret,
        None => {
            tracing::error!(source = %source, "source secret unavailable");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if !PaystackProvider.verify_signature(secret.as_bytes(), &body, signature) {
        state
            .metrics
            .verified_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if state.metrics.should_log_signature_failure() {
            tracing::warn!(source = %source, "webhook signature verification failed");
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .metrics
        .received
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(source = %source, error = %error, "verified webhook was not valid JSON");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let event_type = PaystackProvider.event_type(&payload);
    let decision = decide(&active_config, &payload);
    let matched_route = decision.route.as_ref().map(|route| route.name.as_str());
    if matches!(decision.source, MatchSource::Fallback) && matched_route.is_some() {
        state
            .metrics
            .would_unrouted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let status = if matched_route.is_some() {
        "pending"
    } else {
        "unrouted"
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json");
    let stored_headers = json!({
        "content-type": content_type,
        "x-paystack-signature": signature.unwrap_or_default(),
        "user-agent": headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()),
    });
    let dedupe = dedupe_key(&body);
    let inserted = match state
        .db
        .insert_event(
            &source,
            event_type,
            &body,
            content_type,
            signature.unwrap_or_default(),
            &stored_headers,
            &dedupe,
            matched_route,
            Some(match decision.source {
                MatchSource::MetadataApp => "metadata.app",
                MatchSource::PlanCode => "plan_code",
                MatchSource::Reference => "reference",
                MatchSource::Fallback => "fallback",
            }),
            status,
            decision
                .route
                .as_ref()
                .map(|route| route.destination_url.as_str()),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(source = %source, event_type = %event_type, error = %error, "storing webhook failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match inserted {
        InsertResult::Duplicate => {
            state
                .metrics
                .duplicates
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        InsertResult::Inserted { event_id } => {
            if matched_route.is_none() {
                state
                    .metrics
                    .unrouted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let state_clone = state.clone();
                tokio::spawn(async move {
                    state_clone
                        .alert(format!("Paystack event {event_id} was stored as unrouted"))
                        .await;
                });
            }
        }
    }
    StatusCode::OK.into_response()
}

fn allowed_ip(
    allowed: &[IpAddr],
    trust_proxy: bool,
    headers: &HeaderMap,
    remote: Option<IpAddr>,
) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let ip = if trust_proxy {
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse().ok())
    } else {
        None
    }
    .or(remote);
    ip.is_some_and(|ip| allowed.contains(&ip))
}

#[utoipa::path(
    get,
    path = "/healthz",
    responses((status = 200, description = "Process is alive")),
    tag = "Operations"
)]
pub(crate) async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, description = "Database is reachable"),
        (status = 503, description = "Database is unavailable")
    ),
    tag = "Operations"
)]
pub(crate) async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db.pool)
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(error = %error, "readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses((status = 200, description = "Prometheus metrics", content_type = "text/plain")),
    tag = "Operations"
)]
pub(crate) async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4".to_owned())],
        state.metrics.render(),
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct EventQuery {
    status: Option<String>,
    route: Option<String>,
    r#type: Option<String>,
    since: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/admin/events",
    params(
        ("status" = Option<String>, Query, description = "Event status filter"),
        ("route" = Option<String>, Query, description = "Matched route filter"),
        ("type" = Option<String>, Query, description = "Paystack event type filter"),
        ("since" = Option<String>, Query, description = "RFC3339 lower bound"),
        ("limit" = Option<i64>, Query, description = "Page size from 1 to 100"),
        ("offset" = Option<i64>, Query, description = "Number of rows to skip")
    ),
    responses((status = 200, description = "Matching events", body = Value)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Response {
    if !admin_ok(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let since = match query
        .since
        .as_deref()
        .map(|value| DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc)))
    {
        Some(Ok(value)) => Some(value),
        Some(Err(_)) => return StatusCode::BAD_REQUEST.into_response(),
        None => None,
    };
    match state
        .db
        .list_events(
            query.status.as_deref(),
            query.route.as_deref(),
            query.r#type.as_deref(),
            since,
            query.limit.unwrap_or(50).clamp(1, 100),
            query.offset.unwrap_or(0).max(0),
        )
        .await
    {
        Ok(events) => Json(json!({"events": events})).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing events failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/events/{id}",
    params(("id" = Uuid, Path, description = "Event identifier")),
    responses(
        (status = 200, description = "Event detail", body = crate::db::EventDetail),
        (status = 404, description = "Event was not found")
    ),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn get_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if !admin_ok(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.db.get_event(id).await {
        Ok(Some(event)) => Json(event).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "getting event failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ReplayBody {
    route: Option<String>,
}

#[utoipa::path(
    post,
    path = "/admin/events/{id}/replay",
    params(("id" = Uuid, Path, description = "Event identifier")),
    request_body = ReplayBody,
    responses(
        (status = 202, description = "Event requeued"),
        (status = 404, description = "Event was not found")
    ),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn replay_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ReplayBody>,
) -> Response {
    if !admin_ok(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let active_config = state.runtime_config.read().await.clone();
    match state
        .db
        .replay(id, body.route.as_deref(), &active_config)
        .await
    {
        Ok(true) => StatusCode::ACCEPTED.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "replaying event failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct BulkReplayQuery {
    status: Option<String>,
    route: Option<String>,
}

#[utoipa::path(
    post,
    path = "/admin/replay",
    params(
        ("status" = String, Query, description = "Status to replay"),
        ("route" = String, Query, description = "Destination route name")
    ),
    responses((status = 200, description = "Number of events requeued", body = Value)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn bulk_replay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<BulkReplayQuery>,
) -> Response {
    if !admin_ok(&state, &headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (Some(status), Some(route)) = (query.status.as_deref(), query.route.as_deref()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let active_config = state.runtime_config.read().await.clone();
    match state.db.bulk_replay(status, route, &active_config).await {
        Ok(count) => Json(json!({"requeued": count})).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "bulk replay failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn admin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    state.admin_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    })
}

pub async fn retention_loop(state: Arc<AppState>) {
    loop {
        let retention_days = state.runtime_config.read().await.retention_days;
        if let Err(error) = state.db.prune_delivered(retention_days).await {
            tracing::error!(error = %error, "retention cleanup failed");
        }
        sleep(Duration::from_secs(86_400)).await;
    }
}
