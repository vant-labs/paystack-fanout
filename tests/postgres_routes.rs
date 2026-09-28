use std::{collections::HashMap, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
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
            },
        )]),
        route: vec![],
        fallback: FallbackConfig {
            mode: "unrouted".to_owned(),
        },
        alerts: None,
        retention_days: 90,
    };
    (Arc::new(AppState::new(config, db.clone()).unwrap()), db)
}

async fn request(
    state: Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri).header(
        "authorization",
        format!(
            "Bearer {}",
            std::env::var("ADMIN_BOOTSTRAP_TOKEN")
                .or_else(|_| std::env::var("ADMIN_TOKEN"))
                .unwrap()
        ),
    );
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
