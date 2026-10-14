use std::{collections::HashMap, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use paystack_fanout::{
    AppState,
    app::build_router,
    config::{Config, FallbackConfig, SourceConfig},
    db::Database,
};
use serde_json::Value;
use serial_test::serial;
use tower::ServiceExt;
use uuid::Uuid;

fn can_run() -> bool {
    std::env::var("DATABASE_URL").is_ok()
        && std::env::var("MASTER_ENCRYPTION_KEY").is_ok()
        && (std::env::var("ADMIN_BOOTSTRAP_TOKEN").is_ok() || std::env::var("ADMIN_TOKEN").is_ok())
}

async fn setup() -> (Arc<AppState>, Database) {
    let db = Database::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let config = Config {
        source: HashMap::from([(
            "paystack_main".to_owned(),
            SourceConfig {
                provider: "paystack".to_owned(),
                secret_env: "PAYSTACK_SECRET_KEY".to_owned(),
                allowed_ips: vec![],
                audience: None,
                service_account: None,
                provider_config: HashMap::new(),
            },
        )]),
        route: vec![],
        fallback: FallbackConfig {
            mode: "unrouted".to_owned(),
        },
        alerts: None,
        retention_days: 90,
    };
    let mut state = Arc::new(AppState::new(config, db.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().admin_token = Some("test-admin".to_owned());
    (state, db)
}

async fn request(
    state: Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> axum::response::Response {
    request_with_auth(state, method, uri, body, Some("Bearer test-admin")).await
}

async fn request_with_auth(
    state: Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
    authorization: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(authorization) = authorization {
        builder = builder.header("authorization", authorization);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    build_router(state)
        .oneshot(
            builder
                .body(Body::from(
                    body.map(|value| value.to_string()).unwrap_or_default(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn purchase_jwt(secret: &str, account_id: &str) -> String {
    let claims = serde_json::json!({
        "sub": account_id,
        "exp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600,
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[tokio::test]
#[serial]
async fn route_crud_and_cache_fallback_work() {
    if !can_run() {
        return;
    }
    let (state, db) = setup().await;
    let name = format!("route-{}", Uuid::new_v4());
    let create = request(
        state.clone(),
        "POST",
        "/admin/routes",
        Some(serde_json::json!({
            "name": name.clone(),
            "target_url": "https://example.invalid/timamu",
            "ref_prefix": "tm_",
            "metadata_app": "timamu"
        })),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let routes = request(state.clone(), "GET", "/admin/routes", None).await;
    assert_eq!(routes.status(), StatusCode::OK);
    let routes: Vec<Value> =
        serde_json::from_slice(&to_bytes(routes.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert!(routes.iter().any(|route| route["name"] == name));
    let patch = request(
        state.clone(),
        "PATCH",
        &format!("/admin/routes/{name}"),
        Some(serde_json::json!({"enabled": false})),
    )
    .await;
    assert_eq!(patch.status(), StatusCode::OK);
    let cached = state.cached_routes().await;
    assert!(!cached.iter().any(|route| route.name == name));
    let delete = request(state, "DELETE", &format!("/admin/routes/{name}"), None).await;
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    db.pool.close().await;
}

#[tokio::test]
#[serial]
async fn purchase_endpoints_reject_missing_and_bad_bearer_tokens() {
    if !can_run() {
        return;
    }
    let (state, _db) = setup().await;
    let body = Some(serde_json::json!({
        "provider": "apple",
        "receipt": "signed-transaction"
    }));

    let missing = request_with_auth(
        state.clone(),
        "POST",
        "/v1/purchases/verify",
        body.clone(),
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let bad = request_with_auth(
        state.clone(),
        "GET",
        "/v1/entitlements",
        None,
        Some("Bearer not-a-valid-purchase-token"),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn entitlements_use_jwt_identity_instead_of_cross_account_query() {
    if !can_run() {
        return;
    }
    let (mut state, db) = setup().await;
    let secret = "purchase-jwt-test-secret";
    Arc::get_mut(&mut state).unwrap().purchase_jwt_secret = Some(secret.to_owned());
    sqlx::query("TRUNCATE store_purchases, entitlement_audit CASCADE")
        .execute(&db.pool)
        .await
        .unwrap();

    let token = format!("Bearer {}", purchase_jwt(secret, "account-a"));
    let cross_account_body = request_with_auth(
        state.clone(),
        "POST",
        "/v1/purchases/verify",
        Some(serde_json::json!({
            "provider": "apple",
            "receipt": "signed-transaction",
            "account_id": "account-b"
        })),
        Some(&token),
    )
    .await;
    assert_eq!(
        cross_account_body.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let response = request_with_auth(
        state,
        "GET",
        "/v1/entitlements?account_id=account-b",
        None,
        Some(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["account_id"], "account-a");
    assert_eq!(body["entitlements"], serde_json::json!([]));
}
