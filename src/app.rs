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
    routing::{get, patch, post, put},
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::{Duration, sleep};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    config::{Config, ExtendedRouteMatcher, RouteConfig as ConfigRoute},
    db::{
        Database, DatabaseRoute, DatabaseRouteRecord, DatabaseRouteResponse, InsertResult,
        PurchaseApplyResult,
    },
    metrics::Metrics,
    provider::{
        NormalizedEvent, Provider, ProviderRuntimeSettings, ProviderSettings,
        PurchaseVerificationRequest, provider_for,
    },
    routing::{MatchSource, database_route_records, decide_with_fields, reference},
    security::bearer_matches,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub metrics: Arc<Metrics>,
    pub http: reqwest::Client,
    pub trust_proxy: bool,
    pub admin_token: Option<String>,
    pub bootstrap_token: Option<String>,
    pub purchase_jwt_secret: Option<String>,
    pub purchase_bearer_token: Option<String>,
    pub purchase_bearer_account_id: Option<String>,
    pub cookie_secure: bool,
    pub login_limits: Arc<std::sync::Mutex<HashMap<String, (u32, Instant)>>>,
    pub runtime_config: Arc<tokio::sync::RwLock<Config>>,
    pub runtime_secrets: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    pub runtime_alert_url: Arc<tokio::sync::RwLock<Option<String>>>,
    pub runtime_loaded_at: Arc<tokio::sync::RwLock<Instant>>,
    pub route_cache: Arc<tokio::sync::RwLock<RouteCache>>,
    alert_url_override: Option<String>,
}

pub type RouteCache = Option<(Instant, Vec<DatabaseRouteRecord>)>;

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
            bootstrap_token: std::env::var("ADMIN_BOOTSTRAP_TOKEN")
                .ok()
                .or_else(|| std::env::var("ADMIN_TOKEN").ok()),
            purchase_jwt_secret: std::env::var("PURCHASE_JWT_SECRET")
                .ok()
                .or_else(|| std::env::var("JWT_SECRET").ok()),
            purchase_bearer_token: std::env::var("PURCHASE_BEARER_TOKEN").ok(),
            purchase_bearer_account_id: std::env::var("PURCHASE_BEARER_ACCOUNT_ID").ok(),
            cookie_secure: std::env::var("COOKIE_SECURE")
                .map(|value| !value.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            login_limits: Arc::new(std::sync::Mutex::new(HashMap::new())),
            runtime_config: Arc::new(tokio::sync::RwLock::new(runtime_config)),
            runtime_secrets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            runtime_alert_url: Arc::new(tokio::sync::RwLock::new(None)),
            runtime_loaded_at: Arc::new(tokio::sync::RwLock::new(Instant::now())),
            route_cache: Arc::new(tokio::sync::RwLock::new(None)),
            alert_url_override,
        })
    }

    pub async fn reload_runtime_config(&self) -> anyhow::Result<()> {
        let (config, secrets) = self.db.load_runtime_config(&self.config).await;
        *self.runtime_config.write().await = config;
        *self.runtime_secrets.write().await = secrets;
        *self.runtime_alert_url.write().await = self.db.alert_url_setting().await;
        *self.runtime_loaded_at.write().await = Instant::now();
        Ok(())
    }

    pub async fn refresh_runtime_if_stale(&self) {
        if self.runtime_loaded_at.read().await.elapsed() >= Duration::from_secs(30)
            && let Err(error) = self.reload_runtime_config().await
        {
            tracing::warn!(error = %error, "runtime settings refresh failed");
        }
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

    pub async fn clear_route_cache(&self) {
        *self.route_cache.write().await = None;
    }

    pub async fn cached_route_records(&self) -> Vec<DatabaseRouteRecord> {
        if let Some((loaded_at, routes)) = self.route_cache.read().await.as_ref()
            && loaded_at.elapsed() < Duration::from_secs(30)
        {
            return routes.clone();
        }
        match self.db.list_database_route_records().await {
            Ok(routes) => {
                let routes = routes
                    .into_iter()
                    .filter(|route| route.route.enabled)
                    .collect::<Vec<_>>();
                *self.route_cache.write().await = Some((Instant::now(), routes.clone()));
                routes
            }
            Err(error) => {
                tracing::warn!(error = %error, "route refresh failed; using cached routes");
                self.route_cache
                    .read()
                    .await
                    .as_ref()
                    .map(|(_, routes)| routes.clone())
                    .unwrap_or_default()
            }
        }
    }

    pub async fn cached_routes(&self) -> Vec<DatabaseRoute> {
        self.cached_route_records()
            .await
            .into_iter()
            .map(|record| record.route)
            .collect()
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
        .route("/v1/purchases/verify", post(verify_purchase))
        .route("/v1/entitlements", get(list_entitlements))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/admin/events", get(list_events))
        .route("/admin/events/{id}", get(get_event).post(replay_event))
        .route("/admin/replay", post(bulk_replay))
        .route(
            "/admin/routes",
            get(list_admin_routes).post(create_admin_route),
        )
        .route(
            "/admin/routes/{name}",
            patch(update_admin_route).delete(delete_admin_route),
        )
        .route("/admin/deliveries", get(list_admin_deliveries))
        .route("/admin/settings", get(list_admin_settings))
        .route(
            "/admin/settings/{key}",
            put(set_admin_setting).delete(delete_admin_setting),
        )
        .route("/admin/bootstrap", post(bootstrap_admin))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedProviderRuntime {
    app_identifier: Option<String>,
    environment: Option<String>,
    api_base_url: Option<String>,
    token_url: Option<String>,
    key_id: Option<String>,
    issuer_id: Option<String>,
    private_key: Option<String>,
    service_account_key: Option<String>,
    product_licences: HashMap<String, String>,
}

impl ResolvedProviderRuntime {
    pub(crate) fn borrowed<'a>(
        &'a self,
        source: &'a crate::config::SourceConfig,
    ) -> ProviderRuntimeSettings<'a> {
        ProviderRuntimeSettings {
            app_identifier: self.app_identifier.as_deref(),
            environment: self.environment.as_deref(),
            api_base_url: self.api_base_url.as_deref(),
            token_url: self.token_url.as_deref(),
            key_id: self.key_id.as_deref(),
            issuer_id: self.issuer_id.as_deref(),
            private_key: self.private_key.as_deref(),
            service_account_key: self.service_account_key.as_deref(),
            service_account: source.service_account.as_deref(),
            product_licences: Some(&self.product_licences),
        }
    }
}

pub(crate) fn resolve_provider_runtime(
    source: &crate::config::SourceConfig,
    secret: &str,
) -> ResolvedProviderRuntime {
    let value = |key: &str| source.provider_config.get(key).cloned();
    let env_value = |key: &str| {
        source
            .provider_config
            .get(key)
            .and_then(|name| std::env::var(name).ok())
    };
    let mut product_licences = HashMap::new();
    for (key, value) in &source.provider_config {
        if let Some(product) = key.strip_prefix("product_licence.") {
            product_licences.insert(product.to_owned(), value.clone());
        }
    }
    ResolvedProviderRuntime {
        app_identifier: value("app_identifier"),
        environment: value("environment"),
        api_base_url: value("api_base_url"),
        token_url: value("token_url"),
        key_id: value("key_id").or_else(|| env_value("key_id_env")),
        issuer_id: value("issuer_id").or_else(|| env_value("issuer_id_env")),
        private_key: env_value("private_key_env")
            .or_else(|| (!secret.is_empty()).then(|| secret.to_owned())),
        service_account_key: env_value("service_account_key_env")
            .or_else(|| (!secret.is_empty()).then(|| secret.to_owned())),
        product_licences,
    }
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
    state.refresh_runtime_if_stale().await;
    let active_config = state.runtime_config.read().await.clone();
    let active_secrets = state.runtime_secrets.read().await.clone();
    let Some(source_config) = active_config.source.get(&source) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(provider) = provider_for(&source_config.provider) else {
        tracing::error!(source = %source, provider = %source_config.provider, "unsupported source provider");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !provider.implemented() {
        tracing::warn!(source = %source, provider = provider.name(), "webhook provider is not implemented");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !allowed_ip(
        source_config.allowed_ips.as_slice(),
        state.trust_proxy,
        &headers,
        Some(remote.0.ip()),
    ) {
        tracing::warn!(source = %source, "webhook rejected by IP allowlist");
        return StatusCode::FORBIDDEN.into_response();
    }
    let signature = provider.authenticated_header(&headers);
    let secret = if provider.secret_required() {
        match active_secrets
            .get(&source)
            .cloned()
            .or_else(|| active_config.secret_for(&source).ok())
        {
            Some(secret) => secret,
            None => {
                tracing::error!(source = %source, "source secret unavailable");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        String::new()
    };
    let settings = ProviderSettings {
        audience: source_config.audience.as_deref(),
        service_account: source_config.service_account.as_deref(),
    };
    if !provider
        .authenticate_with_settings(secret.as_bytes(), &headers, &body, settings)
        .await
    {
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
    let provider_runtime = resolve_provider_runtime(source_config, &secret);
    let initial_normalized = provider.normalize_event_with_settings(
        &payload,
        &body,
        provider_runtime.borrowed(source_config),
    );
    let normalized = match initial_normalized {
        Some(event) => provider
            .enrich_normalized_event(
                event.clone(),
                provider_runtime.borrowed(source_config),
                &state.http,
            )
            .await
            .ok()
            .or(Some(event)),
        None => None,
    };
    let event_type = normalized
        .as_ref()
        .map(|event| event.event_type().to_owned())
        .unwrap_or_else(|| provider.event_type(&payload));
    let event_id = normalized
        .as_ref()
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| provider.event_id(&payload, &body));
    let routing_fields = normalized
        .as_ref()
        .map(NormalizedEvent::routing_fields)
        .unwrap_or_else(|| provider.routing_fields(&payload));
    let database_routes = state.cached_route_records().await;
    let database_match = database_route_records(&database_routes, &routing_fields);
    let database_route_id = database_match.map(|route| route.route.id);
    let decision = if let Some(route) = database_match {
        crate::routing::RouteDecision {
            source: crate::routing::match_source(&route.matcher, &routing_fields)
                .unwrap_or(MatchSource::Fallback),
            route: Some(ConfigRoute {
                name: route.route.name.clone(),
                destination_url: route.route.target_url.clone(),
                matcher: crate::config::RouteMatcher::from_extended(route.matcher.clone()),
            }),
        }
    } else {
        decide_with_fields(&active_config, &payload, &routing_fields)
    };
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
    let stored_headers = headers_to_json(&headers, provider);
    if let Some(event) = normalized.as_ref()
        && let Err(error) = apply_entitlement_event(&state.db, event).await
    {
        tracing::warn!(source = %source, error = %error, "normalized purchase event was rejected");
        return StatusCode::CONFLICT.into_response();
    }
    let normalized_body = normalized
        .as_ref()
        .and_then(|event| serde_json::to_vec(event).ok());
    let dedupe = normalized
        .as_ref()
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| provider.dedupe_key(&payload, &body));
    let inserted = match state
        .db
        .insert_event_with_provider_event_id_and_normalized(
            &source,
            &event_type,
            &body,
            normalized_body.as_deref(),
            content_type,
            signature.unwrap_or_default(),
            &stored_headers,
            &dedupe,
            &event_id,
            matched_route,
            Some(match decision.source {
                MatchSource::AppIdentifier => "app_identifier",
                MatchSource::Environment => "environment",
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
            if let Err(error) = state
                .db
                .annotate_delivery(
                    event_id,
                    &event_type,
                    reference(payload.get("data").unwrap_or(&payload)).as_deref(),
                    database_route_id,
                    matched_route.is_some(),
                )
                .await
            {
                tracing::error!(error = %error, event_id = %event_id, "recording delivery metadata failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            if matched_route.is_none() {
                state
                    .metrics
                    .unrouted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let state_clone = state.clone();
                let provider_label = if provider.name() == "paystack" {
                    "Paystack"
                } else {
                    provider.name()
                };
                tokio::spawn(async move {
                    state_clone
                        .alert(format!(
                            "{} event {event_id} was stored as unrouted",
                            provider_label
                        ))
                        .await;
                });
            }
        }
    }
    StatusCode::OK.into_response()
}

async fn apply_entitlement_event(db: &Database, event: &NormalizedEvent) -> anyhow::Result<()> {
    match db.apply_normalized_event(event).await? {
        PurchaseApplyResult::CrossAccountReplay => {
            anyhow::bail!("store purchase is already owned by another account")
        }
        PurchaseApplyResult::Applied
        | PurchaseApplyResult::Unowned
        | PurchaseApplyResult::UnmappedProduct => Ok(()),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyPurchaseBody {
    provider: String,
    #[serde(default)]
    receipt: Option<String>,
    #[serde(alias = "purchaseToken", default)]
    purchase_token: Option<String>,
    #[serde(alias = "productId", default)]
    product_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PurchaseIdentityClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default, alias = "accountId")]
    account_id: Option<String>,
}

fn identity_account_id(claims: PurchaseIdentityClaims) -> Option<String> {
    if let (Some(subject), Some(account_id)) = (&claims.sub, &claims.account_id)
        && subject != account_id
    {
        return None;
    }
    claims
        .account_id
        .or(claims.sub)
        .filter(|value| !value.trim().is_empty())
}

fn verified_purchase_account_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, StatusCode> {
    let Some(authorization) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Some(token) = authorization
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if let Some(secret) = state.purchase_jwt_secret.as_deref() {
        let validation = Validation::new(Algorithm::HS256);
        if let Ok(token_data) = decode::<PurchaseIdentityClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            return identity_account_id(token_data.claims).ok_or(StatusCode::FORBIDDEN);
        }
    }

    let static_token = state
        .purchase_bearer_token
        .as_deref()
        .or(state.admin_token.as_deref())
        .or(state.bootstrap_token.as_deref());
    if static_token.is_some_and(|expected| bearer_matches(expected, Some(authorization))) {
        return state
            .purchase_bearer_account_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(StatusCode::FORBIDDEN);
    }

    Err(StatusCode::UNAUTHORIZED)
}

#[utoipa::path(
    post,
    path = "/v1/purchases/verify",
    request_body = VerifyPurchaseBody,
    responses(
        (status = 200, description = "Verified purchase accepted"),
        (status = 401, description = "Bearer authentication failed"),
        (status = 403, description = "Authenticated identity does not own the store account"),
        (status = 409, description = "Purchase belongs to another account"),
        (status = 422, description = "Store verification failed")
    ),
    security(("admin_bearer" = [])),
    tag = "Purchases"
)]
pub(crate) async fn verify_purchase(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<VerifyPurchaseBody>,
) -> Response {
    let account_id = match verified_purchase_account_id(&state, &headers) {
        Ok(account_id) => account_id,
        Err(status) => return status.into_response(),
    };
    state.refresh_runtime_if_stale().await;
    let provider_name = match body.provider.as_str() {
        "apple" | "apple_server_notifications" => "apple_server_notifications",
        "google" | "google_play" | "google_play_rtdn" => "google_play_rtdn",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "provider must be apple or google"})),
            )
                .into_response();
        }
    };
    let active_config = state.runtime_config.read().await.clone();
    let Some((source_name, source_config)) = active_config
        .source
        .iter()
        .find(|(_, source)| source.provider == provider_name)
    else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "provider is not configured"})),
        )
            .into_response();
    };
    let provider = provider_for(provider_name).expect("validated provider name");
    let secret = state
        .runtime_secrets
        .read()
        .await
        .get(source_name)
        .cloned()
        .or_else(|| active_config.secret_for(source_name).ok())
        .unwrap_or_default();
    let runtime = resolve_provider_runtime(source_config, &secret);
    let receipt = body
        .receipt
        .or(body.purchase_token)
        .filter(|value| !value.trim().is_empty());
    let Some(receipt) = receipt else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "receipt or purchaseToken is required"})),
        )
            .into_response();
    };
    let request = PurchaseVerificationRequest {
        receipt,
        product_id: body.product_id,
    };
    let mut event = match provider
        .verify_purchase(&request, runtime.borrowed(source_config), &state.http)
        .await
    {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(provider = provider.name(), error = %error, "purchase verification failed");
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": "purchase could not be verified"})),
            )
                .into_response();
        }
    };
    let verified_provider_account_id = event.account_id.clone();
    if provider_name == "apple_server_notifications"
        && verified_provider_account_id.as_deref() != Some(account_id.as_str())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(
                json!({"error": "Apple appAccountToken does not match the authenticated account"}),
            ),
        )
            .into_response();
    }
    if provider_name == "google_play_rtdn"
        && verified_provider_account_id
            .as_deref()
            .is_some_and(|provider_account_id| provider_account_id != account_id)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "store account does not match the authenticated account"})),
        )
            .into_response();
    }
    event.account_id = Some(account_id.clone());
    if event.licence.is_none() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "product is not mapped to a licence"})),
        )
            .into_response();
    }
    match state.db.apply_normalized_event(&event).await {
        Ok(PurchaseApplyResult::CrossAccountReplay) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "purchase belongs to another account"})),
            )
                .into_response();
        }
        Ok(PurchaseApplyResult::Applied) => {}
        Ok(PurchaseApplyResult::Unowned | PurchaseApplyResult::UnmappedProduct) => {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        Err(error) => {
            tracing::error!(error = %error, "storing entitlement failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    let raw_body = serde_json::to_vec(&json!({
        "provider": body.provider,
        "receipt": request.receipt,
        "product_id": request.product_id,
        "account_id": account_id,
    }))
    .unwrap_or_default();
    let normalized_body = serde_json::to_vec(&event).unwrap_or_default();
    if let Err(error) = store_normalized_event(
        &state,
        source_name,
        provider,
        &event,
        &raw_body,
        &normalized_body,
    )
    .await
    {
        tracing::error!(error = %error, "storing verified purchase event failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        Json(json!({"status": "verified", "event_id": event.event_id})),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/entitlements",
    responses((status = 200, description = "Current entitlements", body = Value)),
    security(("admin_bearer" = [])),
    tag = "Purchases"
)]
pub(crate) async fn list_entitlements(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let account_id = match verified_purchase_account_id(&state, &headers) {
        Ok(account_id) => account_id,
        Err(status) => return status.into_response(),
    };
    match state.db.list_entitlements(&account_id).await {
        Ok(entitlements) => {
            Json(json!({"account_id": account_id, "entitlements": entitlements})).into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "listing entitlements failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn store_normalized_event(
    state: &AppState,
    source: &str,
    provider: &dyn Provider,
    event: &NormalizedEvent,
    raw_body: &[u8],
    normalized_body: &[u8],
) -> anyhow::Result<()> {
    let fields = event.routing_fields();
    let database_routes = state.cached_route_records().await;
    let database_match = database_route_records(&database_routes, &fields);
    let database_route_id = database_match.map(|route| route.route.id);
    let active_config = state.runtime_config.read().await.clone();
    let decision = if let Some(route) = database_match {
        crate::routing::RouteDecision {
            source: crate::routing::match_source(&route.matcher, &fields)
                .unwrap_or(MatchSource::Fallback),
            route: Some(ConfigRoute {
                name: route.route.name.clone(),
                destination_url: route.route.target_url.clone(),
                matcher: crate::config::RouteMatcher::from_extended(route.matcher.clone()),
            }),
        }
    } else {
        decide_with_fields(&active_config, &Value::Null, &fields)
    };
    let matched_route = decision.route.as_ref().map(|route| route.name.as_str());
    let status = if matched_route.is_some() {
        "pending"
    } else {
        "unrouted"
    };
    let headers = json!({"content-type": "application/json"});
    let inserted = state
        .db
        .insert_event_with_provider_event_id_and_normalized(
            source,
            event.event_type(),
            raw_body,
            Some(normalized_body),
            "application/json",
            "",
            &headers,
            &event.event_id,
            &event.event_id,
            matched_route,
            Some("provider_verification"),
            status,
            decision
                .route
                .as_ref()
                .map(|route| route.destination_url.as_str()),
        )
        .await?;
    if let InsertResult::Inserted { event_id } = inserted {
        state
            .db
            .annotate_delivery(
                event_id,
                event.event_type(),
                Some(&event.product_id),
                database_route_id,
                matched_route.is_some(),
            )
            .await?;
    }
    let _ = provider;
    Ok(())
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

fn headers_to_json(headers: &HeaderMap, provider: &dyn Provider) -> Value {
    let mut object = serde_json::Map::new();
    let mut names = vec![header::CONTENT_TYPE.as_str()];
    names.extend(provider.auth_header_names());
    for name in names {
        let values = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect::<Vec<_>>();
        if values.len() == 1 {
            object.insert(name.to_owned(), Value::String(values[0].clone()));
        } else if !values.is_empty() {
            object.insert(
                name.to_owned(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
    }
    Value::Object(object)
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
    if let Err(error) = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db.pool)
        .await
    {
        tracing::warn!(error = %error, "readiness check failed");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready", "reason": "database unavailable"})),
        );
    }
    let config = state.runtime_config.read().await;
    let secrets = state.runtime_secrets.read().await;
    let missing = config
        .source
        .iter()
        .filter(|(name, source)| {
            provider_for(&source.provider).is_none_or(Provider::secret_required)
                && !secrets.contains_key(*name)
                && std::env::var(&source.secret_env).is_err()
        })
        .map(|(_, source)| source.secret_env.clone())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        (StatusCode::OK, Json(json!({"status": "ready"})))
    } else {
        (
            StatusCode::OK,
            Json(json!({"status": "ready_with_missing_settings", "missing": missing})),
        )
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
    if !api_authorized(&state, &headers, false).await {
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
    if !api_authorized(&state, &headers, false).await {
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
    if !api_authorized(&state, &headers, true).await {
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
    if !api_authorized(&state, &headers, true).await {
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct RouteWriteBody {
    pub name: Option<String>,
    pub target_url: Option<String>,
    pub ref_prefix: Option<String>,
    pub metadata_app: Option<String>,
    pub plan_code_prefix: Option<String>,
    pub app_identifier: Option<String>,
    pub environment: Option<String>,
    pub enabled: Option<bool>,
}

fn valid_environment(environment: Option<&str>) -> bool {
    environment.is_none_or(|value| matches!(value, "production" | "sandbox"))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct SettingWriteBody {
    pub value: String,
    #[serde(default)]
    pub is_secret: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct BootstrapBody {
    pub email: String,
    pub password: String,
}

fn valid_https_target(value: &str) -> bool {
    value.starts_with("https://") && value.len() > "https://".len()
}

async fn api_authorized(state: &AppState, headers: &HeaderMap, write: bool) -> bool {
    if state.admin_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    }) {
        return true;
    }
    if state.bootstrap_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    }) && state.db.user_count().await.ok() == Some(0)
    {
        return true;
    }
    let Some(token) = crate::auth::session_token(headers) else {
        return false;
    };
    state
        .db
        .session_user(&token)
        .await
        .ok()
        .flatten()
        .is_some_and(|user| !write || user.can_write)
}

#[utoipa::path(
    get,
    path = "/admin/routes",
    responses((status = 200, description = "Enabled routes", body = [crate::db::DatabaseRouteResponse])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_routes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_database_route_records().await {
        Ok(routes) => Json(
            routes
                .into_iter()
                .map(DatabaseRouteResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing routes failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/routes",
    request_body = RouteWriteBody,
    responses((status = 201, description = "Route created", body = crate::db::DatabaseRouteResponse)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn create_admin_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RouteWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Some(name), Some(target_url)) = (body.name.as_deref(), body.target_url.as_deref()) else {
        return (StatusCode::BAD_REQUEST, "name and target_url are required").into_response();
    };
    if name.trim().is_empty()
        || !valid_https_target(target_url)
        || !valid_environment(body.environment.as_deref())
        || (body.ref_prefix.is_none()
            && body.metadata_app.is_none()
            && body.plan_code_prefix.is_none()
            && body.app_identifier.is_none()
            && body.environment.is_none())
    {
        return (
            StatusCode::BAD_REQUEST,
            "target_url must be https and at least one match rule is required",
        )
            .into_response();
    }
    match state
        .db
        .create_database_route_with_matcher(
            name,
            target_url,
            &ExtendedRouteMatcher {
                metadata_app: body.metadata_app.clone(),
                plan_code_prefix: body.plan_code_prefix.clone(),
                reference_prefix: body.ref_prefix.clone(),
                app_identifier: body.app_identifier.clone(),
                environment: body.environment.clone(),
            },
            body.enabled.unwrap_or(true),
        )
        .await
    {
        Ok(route) => {
            state.clear_route_cache().await;
            match state.db.find_database_route_record(&route.name).await {
                Ok(Some(record)) => (
                    StatusCode::CREATED,
                    Json(DatabaseRouteResponse::from(record)),
                )
                    .into_response(),
                Ok(None) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                Err(error) => {
                    tracing::error!(error = %error, "loading created route failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "creating route failed");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

#[utoipa::path(
    patch,
    path = "/admin/routes/{name}",
    params(("name" = String, Path, description = "Route name")),
    request_body = RouteWriteBody,
    responses((status = 200, description = "Route updated", body = crate::db::DatabaseRouteResponse)),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn update_admin_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<RouteWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if body
        .target_url
        .as_deref()
        .is_some_and(|value| !valid_https_target(value))
    {
        return (StatusCode::BAD_REQUEST, "target_url must be https").into_response();
    }
    if !valid_environment(body.environment.as_deref()) {
        return (
            StatusCode::BAD_REQUEST,
            "environment must be production or sandbox",
        )
            .into_response();
    }
    match state
        .db
        .update_database_route_with_matcher(
            &name,
            body.target_url.as_deref(),
            body.ref_prefix.as_deref().map(Some),
            body.metadata_app.as_deref().map(Some),
            body.plan_code_prefix.as_deref().map(Some),
            body.app_identifier.as_deref().map(Some),
            body.environment.as_deref().map(Some),
            body.enabled,
        )
        .await
    {
        Ok(Some(route)) => {
            state.clear_route_cache().await;
            match state.db.find_database_route_record(&route.name).await {
                Ok(Some(record)) => Json(DatabaseRouteResponse::from(record)).into_response(),
                Ok(None) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                Err(error) => {
                    tracing::error!(error = %error, "loading updated route failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/admin/routes/{name}",
    params(("name" = String, Path, description = "Route name")),
    responses((status = 204, description = "Route deleted")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn delete_admin_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.delete_database_route(&name).await {
        Ok(true) => {
            state.clear_route_cache().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "deleting route failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct DeliveryQuery {
    reference: Option<String>,
}

#[utoipa::path(
    get,
    path = "/admin/deliveries",
    params(DeliveryQuery),
    responses((status = 200, description = "Delivery records", body = [crate::db::DeliveryView])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<DeliveryQuery>,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_deliveries(query.reference.as_deref()).await {
        Ok(deliveries) => Json(deliveries).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing deliveries failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/admin/settings",
    responses((status = 200, description = "Settings with masked secret values", body = [crate::db::SettingView])),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn list_admin_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !api_authorized(&state, &headers, false).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_settings().await {
        Ok(settings) => Json(settings).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "listing settings failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    put,
    path = "/admin/settings/{key}",
    params(("key" = String, Path, description = "Setting key")),
    request_body = SettingWriteBody,
    responses((status = 204, description = "Setting stored")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn set_admin_setting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<SettingWriteBody>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if key.trim().is_empty() || body.value.is_empty() {
        return (StatusCode::BAD_REQUEST, "key and value are required").into_response();
    }
    let is_secret =
        body.is_secret || key.ends_with("KEY") || key.ends_with("TOKEN") || key.contains("WEBHOOK");
    match state
        .db
        .set_setting(&key, &body.value, is_secret, None)
        .await
    {
        Ok(()) => {
            if let Err(error) = state.reload_runtime_config().await {
                tracing::error!(error = %error, "reloading settings failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "saving setting failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/admin/settings/{key}",
    params(("key" = String, Path, description = "Setting key")),
    responses((status = 204, description = "Setting deleted")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn delete_admin_setting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if !api_authorized(&state, &headers, true).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.delete_setting(&key).await {
        Ok(_) => {
            if let Err(error) = state.reload_runtime_config().await {
                tracing::error!(error = %error, "reloading settings failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "deleting setting failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/bootstrap",
    request_body = BootstrapBody,
    responses((status = 201, description = "First admin created")),
    security(("admin_bearer" = [])),
    tag = "Admin API"
)]
pub(crate) async fn bootstrap_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BootstrapBody>,
) -> Response {
    if !state.bootstrap_token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
    }) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.user_count().await {
        Ok(0) => {
            let Ok(hash) = crate::auth::hash_password(&body.password) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            match state
                .db
                .create_user(&body.email, &hash, crate::auth::Role::Admin)
                .await
            {
                Ok(_) => StatusCode::CREATED.into_response(),
                Err(error) => {
                    tracing::error!(error = %error, "creating first admin failed");
                    StatusCode::BAD_REQUEST.into_response()
                }
            }
        }
        Ok(_) => StatusCode::CONFLICT.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "checking admin bootstrap state failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
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
