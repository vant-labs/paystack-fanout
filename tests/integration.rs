use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

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
use sha2::{Sha256, Sha512};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, Request as WireRequest, Respond, ResponseTemplate,
    matchers::{method, path},
};

type HmacSha512 = Hmac<Sha512>;

fn can_run() -> bool {
    std::env::var("DATABASE_URL").is_ok() && std::env::var("PAYSTACK_SECRET_KEY").is_ok()
}

async fn setup(destination: String, alert_url: Option<String>) -> (Arc<AppState>, Database) {
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
    let state = Arc::new(AppState::new_with_alert_url(config, db.clone(), alert_url).unwrap());
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
    post_source(state, "paystack_main", body, Some(signature)).await
}

async fn post_source(
    state: Arc<AppState>,
    source: &str,
    body: Vec<u8>,
    signature: Option<String>,
) -> StatusCode {
    post_source_with_header(state, source, body, "x-paystack-signature", signature).await
}

async fn post_source_with_header(
    state: Arc<AppState>,
    source: &str,
    body: Vec<u8>,
    header_name: &str,
    signature: Option<String>,
) -> StatusCode {
    let app = build_router(state).layer(Extension(ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        1234,
    )))));
    let mut request =
        Request::post(format!("/in/{source}")).header("content-type", "application/json");
    if let Some(signature) = signature {
        request = request.header(header_name, signature);
    }
    app.oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

fn app_store_connect_signature_with_secret(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!("hmacsha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn app_store_connect_signature(body: &[u8]) -> String {
    app_store_connect_signature_with_secret(&std::env::var("PAYSTACK_SECRET_KEY").unwrap(), body)
}

#[tokio::test]
#[serial]
async fn ingest_rejects_bad_and_missing_signature_and_keeps_paystack_dedupe_key() {
    if !can_run() {
        return;
    }
    let (state, db) = setup("https://example.invalid/destination".into(), None).await;
    let body = br#"{"event":"charge.success","data":{"reference":"bad_sig"}}"#.to_vec();
    assert_eq!(
        post_source(
            state.clone(),
            "paystack_main",
            body.clone(),
            Some("bad".into())
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_source(state.clone(), "paystack_main", body.clone(), None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(post_event(state, body.clone()).await, StatusCode::OK);
    let stored: String =
        sqlx::query_scalar("SELECT dedupe_key FROM events WHERE source = 'paystack_main'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(stored, paystack_fanout::security::dedupe_key(&body));
}

#[tokio::test]
#[serial]
async fn app_store_connect_rejects_tampered_and_wrong_secret_requests_with_401() {
    if !can_run() {
        return;
    }
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
            "apple_connect_main".to_owned(),
            SourceConfig {
                provider: "apple_connect_webhooks".into(),
                secret_env: "PAYSTACK_SECRET_KEY".into(),
                allowed_ips: vec![],
            },
        )]),
        route: vec![],
        fallback: FallbackConfig {
            mode: "unrouted".into(),
        },
        alerts: None,
        retention_days: 90,
    };
    let state = Arc::new(AppState::new(config, db.clone()).unwrap());
    let body = serde_json::to_vec(&json!({
        "data": {
            "type": "buildUploadStateUpdated",
            "id": "build-event-1",
            "attributes": {"appId": "123456789"}
        }
    }))
    .unwrap();
    assert_eq!(
        post_source_with_header(
            state.clone(),
            "apple_connect_main",
            body.clone(),
            "x-apple-signature",
            Some(app_store_connect_signature(&body)),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_source_with_header(
            state.clone(),
            "apple_connect_main",
            br#"{"data":{"type":"tampered"}}"#.to_vec(),
            "x-apple-signature",
            Some(app_store_connect_signature(&body)),
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_source_with_header(
            state,
            "apple_connect_main",
            body.clone(),
            "x-apple-signature",
            Some(app_store_connect_signature_with_secret("wrong", &body)),
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[serial]
async fn ingest_rejects_unimplemented_provider() {
    if !can_run() {
        return;
    }
    let db = Database::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let config = Config {
        source: HashMap::from([(
            "google_main".to_owned(),
            SourceConfig {
                provider: "google_play_rtdn".into(),
                secret_env: "GOOGLE_SECRET".into(),
                allowed_ips: vec![],
            },
        )]),
        route: vec![],
        fallback: FallbackConfig {
            mode: "unrouted".into(),
        },
        alerts: None,
        retention_days: 90,
    };
    let state = Arc::new(AppState::new(config, db).unwrap());
    assert_eq!(
        post_source(state, "google_main", br#"{}"#.to_vec(), None).await,
        StatusCode::UNAUTHORIZED
    );
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
    let (state, db) = setup(format!("{}/destination", server.uri()), None).await;
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
    let (state, db) = setup(format!("{}/destination", server.uri()), None).await;
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

struct SequenceResponder {
    calls: Arc<AtomicUsize>,
}

impl Respond for SequenceResponder {
    fn respond(&self, _request: &WireRequest) -> ResponseTemplate {
        if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            ResponseTemplate::new(500).set_body_string("temporary failure")
        } else {
            ResponseTemplate::new(200)
        }
    }
}

#[tokio::test]
#[serial]
async fn destination_failure_is_retried_then_delivered() {
    if !can_run() {
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/destination"))
        .respond_with(SequenceResponder {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .expect(2)
        .mount(&server)
        .await;
    let (state, db) = setup(format!("{}/destination", server.uri()), None).await;
    let body =
        serde_json::to_vec(&json!({"event":"charge.success","data":{"reference":"test_retry"}}))
            .unwrap();
    assert_eq!(post_event(state.clone(), body).await, StatusCode::OK);
    let delivery = db.claim_delivery().await.unwrap().unwrap();
    paystack_fanout::worker::process_one(&state, delivery).await;
    let event_id = db.list_events(None, None, None, None, 10, 0).await.unwrap()[0].id;
    assert!(db.retry_now(event_id).await.unwrap());
    let delivery = db.claim_delivery().await.unwrap().unwrap();
    paystack_fanout::worker::process_one(&state, delivery).await;
    assert_eq!(
        db.get_event(event_id)
            .await
            .unwrap()
            .unwrap()
            .summary
            .status,
        "delivered"
    );
    assert!(!db.retry_now(event_id).await.unwrap());
    server.verify().await;
}

#[tokio::test]
#[serial]
async fn dead_event_and_unrouted_event_alert() {
    if !can_run() {
        return;
    }
    let destination = MockServer::start().await;
    let alerts = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/destination"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&destination)
        .await;
    Mock::given(method("POST"))
        .and(path("/alert"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&alerts)
        .await;
    let (state, db) = setup(
        format!("{}/destination", destination.uri()),
        Some(format!("{}/alert", alerts.uri())),
    )
    .await;
    let dead_body =
        serde_json::to_vec(&json!({"event":"charge.success","data":{"reference":"test_dead"}}))
            .unwrap();
    assert_eq!(post_event(state.clone(), dead_body).await, StatusCode::OK);
    let dead_id = db.list_events(None, None, None, None, 10, 0).await.unwrap()[0].id;
    sqlx::query("UPDATE deliveries SET attempts = 9 WHERE event_id = $1")
        .bind(dead_id)
        .execute(&db.pool)
        .await
        .unwrap();
    let delivery = db.claim_delivery().await.unwrap().unwrap();
    paystack_fanout::worker::process_one(&state, delivery).await;
    assert_eq!(
        db.get_event(dead_id).await.unwrap().unwrap().summary.status,
        "dead"
    );

    let unrouted_body = serde_json::to_vec(
        &json!({"event":"refund.processed","data":{"transaction_reference":"unknown"}}),
    )
    .unwrap();
    assert_eq!(
        post_event(state.clone(), unrouted_body).await,
        StatusCode::OK
    );
    let events = db
        .list_events(Some("unrouted"), None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    alerts.verify().await;
}

#[tokio::test]
#[serial]
async fn an_unrouted_event_can_be_replayed_to_a_route() {
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
    let (state, db) = setup(format!("{}/destination", server.uri()), None).await;
    let body = serde_json::to_vec(
        &json!({"event":"refund.processed","data":{"transaction_reference":"unknown"}}),
    )
    .unwrap();
    assert_eq!(post_event(state.clone(), body).await, StatusCode::OK);
    let event_id = db
        .list_events(Some("unrouted"), None, None, None, 10, 0)
        .await
        .unwrap()[0]
        .id;
    assert!(
        db.replay(event_id, Some("test"), &state.config)
            .await
            .unwrap()
    );
    let delivery = db.claim_delivery().await.unwrap().unwrap();
    paystack_fanout::worker::process_one(&state, delivery).await;
    assert_eq!(
        db.get_event(event_id)
            .await
            .unwrap()
            .unwrap()
            .summary
            .status,
        "delivered"
    );
    server.verify().await;
}
