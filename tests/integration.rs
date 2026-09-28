use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{ConnectInfo, Extension},
    http::{Request, StatusCode},
};
use hmac::{Hmac, Mac};
use paystack_fanout::{
    AppState,
    app::build_router,
    config::{Config, FallbackConfig, RouteConfig, RouteMatcher, SourceConfig},
    db::Database,
};
use serde_json::json;
use serial_test::serial;
use sha2::Sha512;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

type HmacSha512 = Hmac<Sha512>;

fn can_run() -> bool {
    std::env::var("DATABASE_URL").is_ok() && std::env::var("PAYSTACK_SECRET_KEY").is_ok()
}

async fn setup(destination: String) -> (Arc<AppState>, Database) {
    let db = Database::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    sqlx::query("TRUNCATE delivery_attempts, deliveries, events CASCADE")
        .execute(&db.pool)
        .await
        .unwrap();
    let config = Config {
        source: HashMap::from([(
            String::from("paystack_main"),
            SourceConfig {
                provider: "paystack".into(),
                secret_env: "PAYSTACK_SECRET_KEY".into(),
                allowed_ips: vec![],
            },
        )]),
        route: vec![RouteConfig {
            name: "test".into(),
            destination_url: destination,
            matcher: RouteMatcher {
                metadata_app: Some("test".into()),
                plan_code_prefix: None,
                reference_prefix: Some("test_".into()),
            },
        }],
        fallback: FallbackConfig {
            mode: "unrouted".into(),
        },
        alerts: None,
        retention_days: 90,
    };
    let state = Arc::new(AppState::new(config, db.clone()).unwrap());
    (state, db)
}

fn signed(body: &[u8]) -> String {
    let secret = std::env::var("PAYSTACK_SECRET_KEY").unwrap();
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

async fn post_event(state: Arc<AppState>, body: Vec<u8>) -> StatusCode {
    let signature = signed(&body);
    let app = build_router(state).layer(Extension(ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        1234,
    )))));
    app.oneshot(
        Request::post("/in/paystack_main")
            .header("content-type", "application/json")
            .header("x-paystack-signature", signature)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
#[serial]
async fn ingest_is_deduplicated_and_worker_preserves_body_and_signature() {
    if !can_run() {
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/destination"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let (state, db) = setup(format!("{}/destination", server.uri())).await;
    let body = serde_json::to_vec(
        &json!({"event":"charge.success","data":{"reference":"test_1","metadata":{"app":"test"}}}),
    )
    .unwrap();
    assert_eq!(
        post_event(state.clone(), body.clone()).await,
        StatusCode::OK
    );
    assert_eq!(post_event(state.clone(), body).await, StatusCode::OK);
    let worker = tokio::spawn(paystack_fanout::worker::run_worker(state.clone()));
    for _ in 0..30 {
        if db
            .list_events(None, None, None, None, 10, 0)
            .await
            .unwrap()
            .first()
            .is_some_and(|event| event.status == "delivered")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    worker.abort();
    assert_eq!(
        db.list_events(None, None, None, None, 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    server.verify().await;
}

#[tokio::test]
#[serial]
async fn two_workers_do_not_double_claim_a_delivery() {
    if !can_run() {
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/destination"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
        .expect(1)
        .mount(&server)
        .await;
    let (state, db) = setup(format!("{}/destination", server.uri())).await;
    let body = serde_json::to_vec(&json!({"event":"charge.success","data":{"reference":"test_2"}}))
        .unwrap();
    assert_eq!(post_event(state.clone(), body).await, StatusCode::OK);
    let first = tokio::spawn(paystack_fanout::worker::run_worker(state.clone()));
    let second = tokio::spawn(paystack_fanout::worker::run_worker(state));
    tokio::time::sleep(Duration::from_secs(1)).await;
    first.abort();
    second.abort();
    assert_eq!(
        db.list_events(None, None, None, None, 10, 0)
            .await
            .unwrap()
            .first()
            .unwrap()
            .status,
        "delivered"
    );
    server.verify().await;
}
