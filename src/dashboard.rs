use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    app::AppState,
    auth::{
        Role, SessionUser, clear_session_cookie, csrf_matches, hash_password, random_token,
        session_cookie, session_token, verify_password, verify_totp,
    },
    config::RouteMatcher,
    db::{AuditEntry, EventDetail, EventSummary, HealthPoint, HealthWindow, OverviewStats},
    db::{RouteView, SourceView, UserView},
};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", get(login).post(login_submit))
        .route("/logout", post(logout))
        .route("/admin", get(overview))
        .route("/dashboard/events", get(events))
        .route("/dashboard/events/{id}", get(event_detail))
        .route("/dashboard/events/{id}/replay", post(replay))
        .route("/dashboard/events/{id}/retry", post(retry_now))
        .route("/dashboard/events/{id}/dead", post(move_to_dead))
        .route("/dashboard/events/export.csv", get(export_csv))
        .route("/dashboard/events/export.ndjson", get(export_ndjson))
        .route("/dashboard/retries", get(retries))
        .route("/dashboard/unrouted", get(unrouted))
        .route("/dashboard/audit", get(audit))
        .route("/dashboard/config", get(configuration))
        .route("/dashboard/config/route", post(save_route))
        .route("/dashboard/config/source", post(save_source))
        .route("/dashboard/config/test-route", post(test_route))
        .route("/dashboard/users", get(users))
        .route("/dashboard/users/create", post(create_user))
        .route("/dashboard/users/{id}/disable", post(disable_user))
        .route("/dashboard/users/{id}/reset-2fa", post(reset_2fa))
        .route("/dashboard/settings", get(settings).post(save_settings))
        .route("/static/{*path}", get(static_asset))
}

#[derive(Debug, Clone, Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
}

#[derive(Debug, Clone, Template)]
#[template(path = "overview.html")]
struct OverviewPage {
    user: SessionUser,
    csrf: String,
    stats: OverviewStats,
    health: HealthChart,
    signature_failures: u64,
    success_rate: String,
    recent_failures: Vec<EventSummary>,
}

#[derive(Debug, Clone)]
struct HealthChart {
    window_label: &'static str,
    show_chart: bool,
    points: Vec<HealthPlotPoint>,
    received_path: String,
    delivered_path: String,
}

#[derive(Debug, Clone)]
struct HealthPlotPoint {
    label: String,
    x: String,
    received_y: String,
    delivered_y: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OverviewQuery {
    window: Option<String>,
}

impl OverviewQuery {
    fn health_window(&self) -> HealthWindow {
        match self.window.as_deref() {
            Some("24h") => HealthWindow::Hours24,
            _ => HealthWindow::Days7,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct EventFilters {
    status: Option<String>,
    route: Option<String>,
    event_type: Option<String>,
    page: Option<i64>,
}

impl EventFilters {
    fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }

    fn offset(&self) -> i64 {
        (self.page() - 1) * 50
    }
}

#[derive(Debug, Clone, Template)]
#[template(path = "events.html")]
struct EventsPage {
    user: SessionUser,
    events: Vec<EventSummary>,
    filters: EventFilters,
    csrf: String,
    title: String,
    empty_message: String,
}

#[derive(Debug, Clone, Template)]
#[template(path = "event_detail.html")]
struct EventDetailPage {
    user: SessionUser,
    detail: EventDetail,
    raw_body: String,
    headers_json: String,
    csrf: String,
}

#[derive(Debug, Clone, Template)]
#[template(path = "audit.html")]
struct AuditPage {
    user: SessionUser,
    entries: Vec<AuditEntry>,
    csrf: String,
}

#[derive(Debug, Clone, Template)]
#[template(path = "configuration.html")]
struct ConfigurationPage {
    user: SessionUser,
    sources: Vec<SourceView>,
    routes: Vec<RouteView>,
    csrf: String,
    message: Option<String>,
    error: Option<String>,
    test_result: Option<String>,
}

#[derive(Debug, Clone, Template)]
#[template(path = "users.html")]
struct UsersPage {
    user: SessionUser,
    users: Vec<UserView>,
    csrf: String,
}

#[derive(Debug, Clone, Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    user: SessionUser,
    csrf: String,
    retention_days: u32,
    fallback_mode: String,
    fallback_options: Vec<String>,
    alert_present: bool,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    email: String,
    password: String,
    totp_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayForm {
    csrf: String,
    route: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RouteForm {
    csrf: String,
    name: String,
    destination_url: String,
    metadata_app: Option<String>,
    plan_code_prefix: Option<String>,
    reference_prefix: Option<String>,
    timeout_seconds: i32,
    max_attempts: i32,
    enabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourceForm {
    csrf: String,
    name: String,
    provider: String,
    secret: Option<String>,
    allowed_ips: Option<String>,
    enabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestRouteForm {
    csrf: String,
    route: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserForm {
    csrf: String,
    email: String,
    password: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct UserActionForm {
    csrf: String,
}

#[derive(Debug, Deserialize)]
struct SettingsForm {
    csrf: String,
    retention_days: u32,
    fallback_mode: String,
    alert_webhook_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    status: Option<String>,
    route: Option<String>,
    event_type: Option<String>,
    source: Option<String>,
    raw: Option<bool>,
}

async fn login(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if current_user(&state, &headers)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return Redirect::to("/admin").into_response();
    }
    render(LoginPage { error: None })
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let key = form.email.trim().to_ascii_lowercase();
    if login_blocked(&state, &key) {
        return render(LoginPage {
            error: Some("Too many attempts. Try again shortly.".to_owned()),
        });
    }
    let user = match state.db.find_user_by_email(&key).await {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(error = %error, "dashboard login lookup failed");
            return render(LoginPage {
                error: Some("Sign-in is temporarily unavailable.".to_owned()),
            });
        }
    };
    let valid = user.as_ref().is_some_and(|user| {
        !user.disabled
            && verify_password(&form.password, &user.password_hash)
            && user.totp_secret.as_deref().is_none_or(|secret| {
                form.totp_code.as_deref().is_some_and(|code| {
                    verify_totp(secret, code, chrono::Utc::now().timestamp().max(0) as u64)
                })
            })
    });
    if !valid {
        login_failed(&state, &key);
        return render(LoginPage {
            error: Some("Email or password is incorrect.".to_owned()),
        });
    }
    let user = user.expect("checked above");
    let token = random_token();
    let csrf = random_token();
    if let Err(error) = state.db.create_session(user.id, &token, &csrf).await {
        tracing::error!(error = %error, "dashboard session creation failed");
        return render(LoginPage {
            error: Some("Sign-in is temporarily unavailable.".to_owned()),
        });
    }
    if let Err(error) = state.db.mark_login(user.id).await {
        tracing::warn!(error = %error, "updating last login failed");
    }
    let remote = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim);
    if let Err(error) = state
        .db
        .audit(
            Some(user.id),
            "login",
            Some("user"),
            Some(&user.id.to_string()),
            &Value::Null,
            remote,
        )
        .await
    {
        tracing::warn!(error = %error, "login audit failed");
    }
    let mut response = Redirect::to("/admin").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&token, state.cookie_secure),
    );
    response
}

#[derive(Debug, Deserialize)]
struct LogoutForm {
    csrf: String,
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let token = session_token(&headers);
    if let Some(token) = token.as_deref() {
        if let Ok(Some(user)) = state.db.session_user(token).await {
            if !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
                return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
            }
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "logout",
                    Some("user"),
                    Some(&user.id.to_string()),
                    &Value::Null,
                    None,
                )
                .await;
        }
        let _ = state.db.delete_session(token).await;
    }
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        clear_session_cookie(state.cookie_secure),
    );
    response
}

fn build_health_chart(points: Vec<HealthPoint>, window: HealthWindow) -> HealthChart {
    const LEFT: f64 = 18.0;
    const RIGHT: f64 = 702.0;
    const TOP: f64 = 20.0;
    const BOTTOM: f64 = 150.0;

    let maximum = points
        .iter()
        .flat_map(|point| [point.received, point.delivered])
        .max()
        .unwrap_or(0)
        .max(1) as f64;
    let denominator = points.len().saturating_sub(1).max(1) as f64;
    let plot_points = points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            let x = LEFT + (index as f64 / denominator) * (RIGHT - LEFT);
            let received_y = BOTTOM - (point.received as f64 / maximum) * (BOTTOM - TOP);
            let delivered_y = BOTTOM - (point.delivered as f64 / maximum) * (BOTTOM - TOP);
            HealthPlotPoint {
                label: match window {
                    HealthWindow::Hours24 => point.bucket.format("%H:%M").to_string(),
                    HealthWindow::Days7 => point.bucket.format("%m-%d").to_string(),
                },
                x: format!("{x:.1}"),
                received_y: format!("{received_y:.1}"),
                delivered_y: format!("{delivered_y:.1}"),
            }
        })
        .collect::<Vec<_>>();
    let received_path = plot_points
        .iter()
        .map(|point| format!("{},{}", point.x, point.received_y))
        .collect::<Vec<_>>()
        .join(" ");
    let delivered_path = plot_points
        .iter()
        .map(|point| format!("{},{}", point.x, point.delivered_y))
        .collect::<Vec<_>>()
        .join(" ");

    HealthChart {
        window_label: match window {
            HealthWindow::Hours24 => "24 hours",
            HealthWindow::Days7 => "7 days",
        },
        show_chart: plot_points.len() >= 2,
        points: plot_points,
        received_path,
        delivered_path,
    }
}

async fn overview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<OverviewQuery>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let stats = match state.db.overview_stats().await {
        Ok(stats) => stats,
        Err(error) => return server_error(error),
    };
    let health = match state.db.overview_health(query.health_window()).await {
        Ok(points) => build_health_chart(points, query.health_window()),
        Err(error) => return server_error(error),
    };
    let recent_failures = match state
        .db
        .list_events(Some("dead"), None, None, None, 8, 0)
        .await
    {
        Ok(events) => events,
        Err(error) => return server_error(error),
    };
    let success_rate = if stats.total_with_delivery == 0 {
        "—".to_owned()
    } else {
        format!(
            "{:.1}%",
            (stats.delivered_with_delivery as f64 / stats.total_with_delivery as f64) * 100.0
        )
    };
    render(OverviewPage {
        user,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        stats,
        health,
        signature_failures: state
            .metrics
            .verified_failed
            .load(std::sync::atomic::Ordering::Relaxed),
        success_rate,
        recent_failures,
    })
}

async fn events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(filters): Query<EventFilters>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let events = match state
        .db
        .list_events(
            filters.status.as_deref(),
            filters.route.as_deref(),
            filters.event_type.as_deref(),
            None,
            50,
            filters.offset(),
        )
        .await
    {
        Ok(events) => events,
        Err(error) => return server_error(error),
    };
    render(EventsPage {
        user,
        empty_message: if filters.status.as_deref() == Some("unrouted") {
            "No unrouted events need attention."
        } else {
            "No events match these filters."
        }
        .to_owned(),
        title: "Events".to_owned(),
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        events,
        filters,
    })
}

async fn retries(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let filters = EventFilters {
        status: Some("retrying".to_owned()),
        ..EventFilters::default()
    };
    let events = match state
        .db
        .list_events(Some("retrying"), None, None, None, 50, 0)
        .await
    {
        Ok(events) => events,
        Err(error) => return server_error(error),
    };
    render(EventsPage {
        user,
        events,
        filters,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        title: "Retries and dead letters".to_owned(),
        empty_message: "The delivery queue is clear.".to_owned(),
    })
}

async fn unrouted(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let filters = EventFilters {
        status: Some("unrouted".to_owned()),
        ..EventFilters::default()
    };
    let events = match state
        .db
        .list_events(Some("unrouted"), None, None, None, 50, 0)
        .await
    {
        Ok(events) => events,
        Err(error) => return server_error(error),
    };
    render(EventsPage {
        user,
        events,
        filters,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        title: "Unrouted".to_owned(),
        empty_message: "Every event is currently assigned to a route.".to_owned(),
    })
}

async fn event_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let detail = match state.db.get_event(id).await {
        Ok(Some(detail)) => detail,
        Ok(None) => return (StatusCode::NOT_FOUND, "Event not found").into_response(),
        Err(error) => return server_error(error),
    };
    let raw_body = serde_json::from_str::<Value>(&detail.raw_body)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
        .unwrap_or_else(|| detail.raw_body.clone());
    let headers_json = masked_headers(&detail.headers);
    render(EventDetailPage {
        user,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        detail,
        raw_body,
        headers_json,
    })
}

async fn replay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ReplayForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.role.can_write() || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
    }
    let active_config = state.runtime_config.read().await.clone();
    match state
        .db
        .replay(id, form.route.as_deref(), &active_config)
        .await
    {
        Ok(true) => {
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "replay",
                    Some("event"),
                    Some(&id.to_string()),
                    &Value::Null,
                    None,
                )
                .await;
            Redirect::to(&format!("/dashboard/events/{id}")).into_response()
        }
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            "This event has no configured destination",
        )
            .into_response(),
        Err(error) => server_error(error),
    }
}

async fn retry_now(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ReplayForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.can_write || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
    }
    match state.db.retry_now(id).await {
        Ok(true) => {
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "retry_now",
                    Some("event"),
                    Some(&id.to_string()),
                    &Value::Null,
                    None,
                )
                .await;
            Redirect::to(&format!("/dashboard/events/{id}")).into_response()
        }
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            "This event is not waiting for retry",
        )
            .into_response(),
        Err(error) => server_error(error),
    }
}

async fn move_to_dead(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<ReplayForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.can_write || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
    }
    match state.db.move_to_dead(id).await {
        Ok(true) => {
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "move_to_dead",
                    Some("event"),
                    Some(&id.to_string()),
                    &Value::Null,
                    None,
                )
                .await;
            Redirect::to(&format!("/dashboard/events/{id}")).into_response()
        }
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            "This event cannot be moved to dead letters",
        )
            .into_response(),
        Err(error) => server_error(error),
    }
}

async fn export_csv(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Response {
    export_events(state, headers, query, false).await
}

async fn export_ndjson(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Response {
    export_events(state, headers, query, true).await
}

async fn export_events(
    state: Arc<AppState>,
    headers: HeaderMap,
    query: ExportQuery,
    ndjson: bool,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let _ = state
        .db
        .audit(
            Some(user.id),
            if ndjson {
                "export_ndjson"
            } else {
                "export_csv"
            },
            Some("events"),
            None,
            &serde_json::json!({"raw": query.raw.unwrap_or(false)}),
            None,
        )
        .await;
    let include_raw = query.raw.unwrap_or(false);
    let rows = state.db.clone().export_events(
        query.status.clone(),
        query.route.clone(),
        query.event_type.clone(),
        query.source.clone(),
    );
    let data = rows.map(move |row| match row {
        Ok(row) => {
            let id: Uuid = row.try_get("id").map_err(|error| std::io::Error::other(error.to_string()))?;
            let source: String = row.try_get("source").map_err(|error| std::io::Error::other(error.to_string()))?;
            let event_type: String = row.try_get("event_type").map_err(|error| std::io::Error::other(error.to_string()))?;
            let route: Option<String> = row.try_get("matched_route").map_err(|error| std::io::Error::other(error.to_string()))?;
            let status: String = row.try_get("status").map_err(|error| std::io::Error::other(error.to_string()))?;
            let received_at: chrono::DateTime<chrono::Utc> = row.try_get("received_at").map_err(|error| std::io::Error::other(error.to_string()))?;
            let delivered_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("delivered_at").map_err(|error| std::io::Error::other(error.to_string()))?;
            let raw_body: Vec<u8> = row.try_get("raw_body").map_err(|error| std::io::Error::other(error.to_string()))?;
            let output = if ndjson {
                serde_json::to_vec(&serde_json::json!({"id": id, "source": source, "event_type": event_type, "route": route, "status": status, "received_at": received_at, "delivered_at": delivered_at, "raw_body": include_raw.then(|| String::from_utf8_lossy(&raw_body).into_owned())})).map_err(|error| std::io::Error::other(error.to_string()))?
            } else {
                let raw_text = if include_raw {
                    String::from_utf8_lossy(&raw_body).into_owned()
                } else {
                    String::new()
                };
                let fields = [id.to_string(), source, event_type, route.unwrap_or_default(), status, received_at.to_rfc3339(), delivered_at.map(|value| value.to_rfc3339()).unwrap_or_default(), raw_text];
                fields.iter().map(|field| csv_field(field)).collect::<Vec<_>>().join(",").into_bytes()
            };
            Ok::<Bytes, std::io::Error>(Bytes::from([output, b"\n".to_vec()].concat()))
        }
        Err(error) => Err(std::io::Error::other(error.to_string())),
    });
    let header_line = if ndjson {
        Bytes::new()
    } else {
        Bytes::from_static(b"id,source,event_type,route,status,received_at,delivered_at,raw_body\n")
    };
    let stream =
        futures_util::stream::once(async move { Ok::<Bytes, std::io::Error>(header_line) })
            .chain(data);
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if ndjson {
            "application/x-ndjson"
        } else {
            "text/csv; charset=utf-8"
        }),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(if ndjson {
            "attachment; filename=fanout-events.ndjson"
        } else {
            "attachment; filename=fanout-events.csv"
        }),
    );
    response
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

async fn audit(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    match state.db.list_audit(100, 0).await {
        Ok(entries) => render(AuditPage {
            user,
            entries,
            csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        }),
        Err(error) => server_error(error),
    }
}

async fn users(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.role.can_manage() {
        return (StatusCode::FORBIDDEN, "Owner access is required").into_response();
    }
    match state.db.list_users().await {
        Ok(users) => render(UsersPage {
            user,
            users,
            csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        }),
        Err(error) => server_error(error),
    }
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.role.can_manage() || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Owner access is required").into_response();
    }
    let Some(role) = Role::parse(&form.role) else {
        return (StatusCode::BAD_REQUEST, "Invalid role").into_response();
    };
    if role == Role::Owner {
        return (
            StatusCode::BAD_REQUEST,
            "Only the first account is created as owner",
        )
            .into_response();
    }
    if form.email.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Email is required").into_response();
    }
    let password_hash = match hash_password(&form.password) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match state
        .db
        .create_user(&form.email, &password_hash, role)
        .await
    {
        Ok(id) => {
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "user_create",
                    Some("user"),
                    Some(&id.to_string()),
                    &serde_json::json!({"role": role.to_string()}),
                    None,
                )
                .await;
            Redirect::to("/dashboard/users").into_response()
        }
        Err(error) => server_error(error),
    }
}

async fn disable_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UserActionForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.role.can_manage() || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Owner access is required").into_response();
    }
    if id == user.id {
        return (
            StatusCode::BAD_REQUEST,
            "The current owner cannot be disabled",
        )
            .into_response();
    }
    match state.db.set_user_disabled(id, true).await {
        Ok(true) => {
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "user_disable",
                    Some("user"),
                    Some(&id.to_string()),
                    &Value::Null,
                    None,
                )
                .await;
            Redirect::to("/dashboard/users").into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(error),
    }
}

async fn reset_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UserActionForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.role.can_manage() || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Owner access is required").into_response();
    }
    match state.db.reset_totp(id).await {
        Ok(true) => {
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "user_reset_2fa",
                    Some("user"),
                    Some(&id.to_string()),
                    &Value::Null,
                    None,
                )
                .await;
            Redirect::to("/dashboard/users").into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error(error),
    }
}

async fn settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let config = state.runtime_config.read().await.clone();
    let mut fallback_options = vec!["unrouted".to_owned()];
    fallback_options.extend(
        config
            .route
            .iter()
            .map(|route| format!("route:{}", route.name)),
    );
    render(SettingsPage {
        user,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        retention_days: config.retention_days,
        fallback_mode: config.fallback.mode,
        fallback_options,
        alert_present: state.runtime_alert_url.read().await.is_some(),
    })
}

async fn save_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.can_write || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
    }
    if let Err(error) = state
        .db
        .save_settings(
            form.retention_days,
            &form.fallback_mode,
            form.alert_webhook_url.as_deref(),
        )
        .await
    {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    if let Err(error) = state.reload_runtime_config().await {
        return server_error(error);
    }
    let _ = state
        .db
        .audit(
            Some(user.id),
            "settings_edit",
            Some("settings"),
            None,
            &serde_json::json!({
                "retention_days": form.retention_days,
                "fallback_mode": form.fallback_mode
            }),
            None,
        )
        .await;
    Redirect::to("/dashboard/settings").into_response()
}

async fn configuration(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let sources = match state.db.list_sources().await {
        Ok(sources) => sources,
        Err(error) => return server_error(error),
    };
    let routes = match state.db.list_routes().await {
        Ok(routes) => routes,
        Err(error) => return server_error(error),
    };
    render(ConfigurationPage {
        user,
        sources,
        routes,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        message: None,
        error: None,
        test_result: None,
    })
}

async fn save_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<RouteForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.can_write || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
    }
    let name = form.name.trim();
    if name.is_empty()
        || !(form.destination_url.starts_with("https://")
            || form.destination_url.starts_with("http://"))
    {
        return (
            StatusCode::BAD_REQUEST,
            "Route name and an http(s) destination are required",
        )
            .into_response();
    }
    if !(1..=60).contains(&form.timeout_seconds) || !(1..=10).contains(&form.max_attempts) {
        return (
            StatusCode::BAD_REQUEST,
            "Timeout must be 1–60 seconds and attempts must be 1–10",
        )
            .into_response();
    }
    let matcher = RouteMatcher {
        metadata_app: clean_option(form.metadata_app),
        plan_code_prefix: clean_option(form.plan_code_prefix),
        reference_prefix: clean_option(form.reference_prefix),
    };
    match state
        .db
        .save_route(
            name,
            form.destination_url.trim(),
            &matcher,
            form.timeout_seconds,
            form.max_attempts,
            form.enabled.is_some(),
        )
        .await
    {
        Ok(()) => {
            if let Err(error) = state.reload_runtime_config().await {
                return server_error(error);
            }
            state.clear_route_cache().await;
            let _ = state
                .db
                .audit(
                    Some(user.id),
                    "route_edit",
                    Some("route"),
                    Some(name),
                    &serde_json::json!({"enabled": form.enabled.is_some()}),
                    None,
                )
                .await;
            Redirect::to("/dashboard/config").into_response()
        }
        Err(error) => server_error(error),
    }
}

async fn save_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SourceForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !user.role.can_manage() || !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Owner access is required").into_response();
    }
    let name = form.name.trim();
    if name.is_empty() || form.provider.trim() != "paystack" {
        return (
            StatusCode::BAD_REQUEST,
            "A source name and the paystack provider are required",
        )
            .into_response();
    }
    let allowed_ips = form
        .allowed_ips
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Err(error) = allowed_ips.iter().try_for_each(|value| {
        value
            .parse::<std::net::IpAddr>()
            .map(|_| ())
            .map_err(|_| value)
    }) {
        return (
            StatusCode::BAD_REQUEST,
            format!("Invalid source IP: {error}"),
        )
            .into_response();
    }
    let secret = form
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match state
        .db
        .save_source(
            name,
            form.provider.trim(),
            secret,
            &allowed_ips,
            form.enabled.is_some(),
        )
        .await
    {
        Ok(()) => {
            if let Err(error) = state.reload_runtime_config().await {
                return server_error(error);
            }
            let _ = state.db.audit(Some(user.id), "source_edit", Some("source"), Some(name), &serde_json::json!({"enabled": form.enabled.is_some(), "secret_changed": secret.is_some()}), None).await;
            Redirect::to("/dashboard/config").into_response()
        }
        Err(error) => server_error(error),
    }
}

async fn test_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<TestRouteForm>,
) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_matches(&user.csrf_token, Some(&form.csrf)) {
        return (StatusCode::FORBIDDEN, "Action not permitted").into_response();
    }
    let payload = match serde_json::from_str::<Value>(&form.payload) {
        Ok(payload) => payload,
        Err(_) => return (StatusCode::BAD_REQUEST, "Payload must be valid JSON").into_response(),
    };
    let config = state.runtime_config.read().await.clone();
    let decision = crate::routing::decide(&config, &payload);
    let test_result = match decision.route {
        Some(route) if route.name == form.route => {
            format!("Matched {} via {:?}.", route.name, decision.source)
        }
        Some(route) => format!(
            "Payload matched {} instead of {} via {:?}.",
            route.name, form.route, decision.source
        ),
        None => format!("No route matched; fallback is {}.", config.fallback.mode),
    };
    let sources = state.db.list_sources().await.unwrap_or_default();
    let routes = state.db.list_routes().await.unwrap_or_default();
    render(ConfigurationPage {
        user,
        sources,
        routes,
        csrf: current_csrf(&state, &headers).await.unwrap_or_default(),
        message: None,
        error: None,
        test_result: Some(test_result),
    })
}

fn clean_option(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

async fn static_asset(Path(path): Path<String>) -> Response {
    let (body, content_type): (&[u8], &str) = match path.as_str() {
        "app.css" => (
            include_bytes!("../static/app.css"),
            "text/css; charset=utf-8",
        ),
        "app.js" => (
            include_bytes!("../static/app.js"),
            "text/javascript; charset=utf-8",
        ),
        "htmx-2.0.6.min.js" => (
            include_bytes!("../static/htmx-2.0.6.min.js"),
            "text/javascript; charset=utf-8",
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}

async fn current_user(
    state: &AppState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<SessionUser>> {
    let Some(token) = session_token(headers) else {
        return Ok(None);
    };
    let user = state.db.session_user(&token).await?;
    if user.is_some() {
        state.db.touch_session(&token).await?;
    }
    Ok(user)
}

async fn require_user(state: &AppState, headers: &HeaderMap) -> Option<SessionUser> {
    current_user(state, headers).await.ok().flatten()
}

async fn current_csrf(state: &AppState, headers: &HeaderMap) -> Option<String> {
    current_user(state, headers)
        .await
        .ok()
        .flatten()
        .map(|user| user.csrf_token)
}

fn login_blocked(state: &AppState, key: &str) -> bool {
    let mut limits = state.login_limits.lock().expect("login limiter lock");
    if let Some((attempts, started)) = limits.get(key).copied() {
        if started.elapsed().as_secs() > 300 {
            limits.remove(key);
            false
        } else {
            attempts >= 5
        }
    } else {
        false
    }
}

fn login_failed(state: &AppState, key: &str) {
    let mut limits = state.login_limits.lock().expect("login limiter lock");
    let entry = limits
        .entry(key.to_owned())
        .or_insert((0, std::time::Instant::now()));
    entry.0 = entry.0.saturating_add(1);
}

fn masked_headers(headers: &Value) -> String {
    let mut value = headers.clone();
    if let Some(signature) = value.get_mut("x-paystack-signature")
        && let Some(text) = signature.as_str()
    {
        *signature = Value::String(format!("{}…", text.chars().take(8).collect::<String>()));
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_owned())
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => {
            let mut response = Html(body).into_response();
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"));
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("same-origin"),
            );
            response
        }
        Err(error) => server_error(error),
    }
}

fn server_error(error: impl std::fmt::Display) -> Response {
    tracing::error!(error = %error, "dashboard request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}
