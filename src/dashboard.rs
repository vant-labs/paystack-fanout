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
        SessionUser, clear_session_cookie, csrf_matches, random_token, session_cookie,
        session_token, verify_password,
    },
    db::{AuditEntry, EventDetail, EventSummary, OverviewStats},
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
    stats: OverviewStats,
    signature_failures: u64,
    success_rate: String,
    recent_failures: Vec<EventSummary>,
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
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct ReplayForm {
    csrf: String,
    route: Option<String>,
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
    let valid = user
        .as_ref()
        .is_some_and(|user| !user.disabled && verify_password(&form.password, &user.password_hash));
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

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let token = session_token(&headers);
    if let Some(token) = token.as_deref() {
        if let Ok(Some(user)) = state.db.session_user(token).await {
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

async fn overview(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let stats = match state.db.overview_stats().await {
        Ok(stats) => stats,
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
        stats,
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
    match state
        .db
        .replay(id, form.route.as_deref(), &state.config)
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
        Ok(entries) => render(AuditPage { user, entries }),
        Err(error) => server_error(error),
    }
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
