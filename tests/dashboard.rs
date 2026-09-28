use std::{collections::HashMap, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use paystack_fanout::{
    AppState,
    app::build_router,
    auth::{Role, hash_password},
    config::{Config, FallbackConfig, RouteConfig, RouteMatcher, SourceConfig},
    db::{Database, HealthWindow},
};
use serial_test::serial;
use tower::ServiceExt;
use uuid::Uuid;

fn can_run() -> bool {
    std::env::var("DATABASE_URL").is_ok() && std::env::var("PAYSTACK_SECRET_KEY").is_ok()
}

async fn setup() -> (Arc<AppState>, Database) {
    let db = Database::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    sqlx::query("TRUNCATE sessions, audit_logs, users CASCADE")
        .execute(&db.pool)
        .await
        .unwrap();
    let config = Config {
        source: HashMap::from([(
            "paystack_main".to_owned(),
            SourceConfig {
                provider: "paystack".to_owned(),
                secret_env: "PAYSTACK_SECRET_KEY".to_owned(),
                allowed_ips: vec![],
            },
        )]),
        route: vec![RouteConfig {
            name: "test".to_owned(),
            destination_url: "http://localhost/test".to_owned(),
            matcher: RouteMatcher::default(),
        }],
        fallback: FallbackConfig {
            mode: "unrouted".to_owned(),
        },
        alerts: None,
        retention_days: 90,
    };
    let state = Arc::new(AppState::new(config, db.clone()).unwrap());
    (state, db)
}

async fn request(
    state: Arc<AppState>,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/x-www-form-urlencoded");
    }
    build_router(state)
        .oneshot(
            builder
                .body(Body::from(body.unwrap_or_default().to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn login(state: Arc<AppState>, email: &str, password: &str) -> (String, String) {
    let response = request(
        state.clone(),
        "POST",
        "/login",
        None,
        Some(&format!("email={email}&password={password}")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let token = set_cookie.split(';').next().unwrap().to_owned();
    let token_value = token.split('=').nth(1).unwrap();
    let user = state.db.session_user(token_value).await.unwrap().unwrap();
    (token, user.csrf_token)
}

#[tokio::test]
#[serial]
async fn login_sets_session_and_rejects_missing_csrf() {
    if !can_run() {
        return;
    }
    let (state, db) = setup().await;
    db.create_owner(
        "owner@example.com",
        &hash_password("long secure password").unwrap(),
    )
    .await
    .unwrap();
    let (cookie, _) = login(state.clone(), "owner@example.com", "long secure password").await;
    let page = request(state.clone(), "GET", "/admin", Some(&cookie), None).await;
    assert_eq!(page.status(), StatusCode::OK);
    let response = request(
        state,
        "POST",
        &format!("/dashboard/events/{}/replay", Uuid::new_v4()),
        Some(&cookie),
        Some("route=test"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[serial]
async fn viewer_cannot_replay() {
    if !can_run() {
        return;
    }
    let (state, db) = setup().await;
    db.create_owner(
        "owner@example.com",
        &hash_password("long secure password").unwrap(),
    )
    .await
    .unwrap();
    db.create_user(
        "viewer@example.com",
        &hash_password("long secure password").unwrap(),
        Role::Viewer,
    )
    .await
    .unwrap();
    let (cookie, csrf) = login(state.clone(), "viewer@example.com", "long secure password").await;
    let response = request(
        state,
        "POST",
        &format!("/dashboard/events/{}/replay", Uuid::new_v4()),
        Some(&cookie),
        Some(&format!("csrf={csrf}&route=test")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn repeated_bad_logins_are_limited() {
    if !can_run() {
        return;
    }
    let (state, db) = setup().await;
    db.create_owner(
        "owner@example.com",
        &hash_password("long secure password").unwrap(),
    )
    .await
    .unwrap();
    for _ in 0..5 {
        let response = request(
            state.clone(),
            "POST",
            "/login",
            None,
            Some("email=owner@example.com&password=wrong password"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = request(
        state,
        "POST",
        "/login",
        None,
        Some("email=owner@example.com&password=long secure password"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn matcher_and_csv_export_are_available_to_signed_in_users() {
    if !can_run() {
        return;
    }
    let (state, db) = setup().await;
    db.create_owner(
        "owner@example.com",
        &hash_password("long secure password").unwrap(),
    )
    .await
    .unwrap();
    db.insert_event(
        "paystack_main",
        "charge.success",
        br#"{"event":"charge.success","data":{"metadata":{"app":"test"}}}"#,
        "application/json",
        "signature",
        &serde_json::json!({"content-type":"application/json"}),
        "dashboard-export-key",
        Some("test"),
        Some("metadata.app"),
        "pending",
        Some("http://localhost/test"),
    )
    .await
    .unwrap();
    let (cookie, csrf) = login(state.clone(), "owner@example.com", "long secure password").await;
    let test_response = request(state.clone(), "POST", "/dashboard/config/test-route", Some(&cookie), Some(&format!("csrf={csrf}&route=test&payload=%7B%22data%22%3A%7B%22metadata%22%3A%7B%22app%22%3A%22test%22%7D%7D%7D"))).await;
    assert_eq!(test_response.status(), StatusCode::OK);
    let export = request(
        state,
        "GET",
        "/dashboard/events/export.csv",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(export.status(), StatusCode::OK);
    assert_eq!(
        export.headers().get("content-type").unwrap(),
        "text/csv; charset=utf-8"
    );
    let body = to_bytes(export.into_body(), usize::MAX).await.unwrap();
    assert!(body.starts_with(b"id,source,event_type"));
    assert!(
        body.windows(b"charge.success".len())
            .any(|window| window == b"charge.success")
    );
}

#[tokio::test]
#[serial]
async fn swagger_docs_are_available_at_docs() {
    if !can_run() {
        return;
    }
    let (state, _) = setup().await;
    let ui = request(state.clone(), "GET", "/docs", None, None).await;
    assert_eq!(ui.status(), StatusCode::SEE_OTHER);
    assert_eq!(ui.headers().get("location").unwrap(), "/docs/");
    let ui = request(state.clone(), "GET", "/docs/", None, None).await;
    assert_eq!(ui.status(), StatusCode::OK);
    let ui_body = to_bytes(ui.into_body(), usize::MAX).await.unwrap();
    assert!(
        ui_body
            .windows(b"Swagger UI".len())
            .any(|window| window == b"Swagger UI")
    );

    let spec = request(state, "GET", "/api-docs/openapi.json", None, None).await;
    assert_eq!(spec.status(), StatusCode::OK);
    let spec_body = to_bytes(spec.into_body(), usize::MAX).await.unwrap();
    assert!(
        spec_body
            .windows(b"/admin/events".len())
            .any(|window| window == b"/admin/events")
    );
}

#[tokio::test]
#[serial]
async fn overview_health_uses_one_real_postgres_point_and_shows_empty_state() {
    if !can_run() {
        return;
    }
    let (state, db) = setup().await;
    sqlx::query("TRUNCATE delivery_attempts, deliveries, events CASCADE")
        .execute(&db.pool)
        .await
        .unwrap();
    db.create_owner(
        "owner@example.com",
        &hash_password("long secure password").unwrap(),
    )
    .await
    .unwrap();
    db.insert_event(
        "paystack_main",
        "charge.success",
        br#"{"event":"charge.success","data":{"reference":"tm_chart_1"}}"#,
        "application/json",
        "signature",
        &serde_json::json!({"content-type":"application/json"}),
        "overview-health-key",
        Some("test"),
        Some("reference_prefix"),
        "pending",
        Some("http://localhost/test"),
    )
    .await
    .unwrap();

    let points = db.overview_health(HealthWindow::Hours24).await.unwrap();
    assert_eq!(points.len(), 1);
    assert_eq!(points[0].received, 1);
    assert_eq!(points[0].delivered, 0);

    let (cookie, _) = login(state.clone(), "owner@example.com", "long secure password").await;
    let response = request(state, "GET", "/admin?window=24h", Some(&cookie), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(
        body.windows(b"Not enough data yet".len())
            .any(|window| { window == b"Not enough data yet" })
    );
}
