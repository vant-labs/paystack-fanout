use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use paystack_fanout::{
    AppState,
    app::build_router,
    auth::{Role, hash_password},
    config::{Config, FallbackConfig, RouteConfig, RouteMatcher, SourceConfig},
    db::Database,
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
