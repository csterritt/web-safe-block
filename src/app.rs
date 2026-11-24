//! Router assembly, per-request event reporting, and state cleanup.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::handler::Handler;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::auth::{login, login_redirect, logout, logout_page};
use crate::monitor::{Event, EventKind, EventQueue, Outcome, truncate_at};
use crate::proxy::proxy_or_login;
use crate::rate_limit::RATE_LIMIT_WINDOW;
use crate::sessions::reload_sessions;
use crate::state::{AppState, Config};
use crate::util::{LOGIN_PATH, LOGOUT_PATH, client_key};

/// Login form size cap; enforced both by the body limit and by
/// `login_body_deadline` while it buffers the body.
const LOGIN_BODY_LIMIT: usize = 4096;

/// Build the public-facing router. Every request is reported to `events`.
/// Loads the persisted sessions before serving; errors if users.db cannot
/// be read. Must be called inside a Tokio runtime: it spawns a background
/// purge task that lives for the life of that runtime.
pub fn build_router(config: Config, events: Arc<EventQueue>) -> Result<Router, String> {
    let state = AppState::new(config, events);
    {
        let mut last = state.session_writes.try_lock().expect("uncontended");
        *last = reload_sessions(&state).map_err(|e| format!("cannot load sessions: {e}"))?;
    }
    spawn_purger(state.clone());
    Ok(Router::new()
        .route(
            LOGIN_PATH,
            get(login_redirect)
                .post(login.layer(middleware::from_fn_with_state(
                    state.config.limits.request_body_timeout,
                    login_body_deadline,
                )))
                .layer(DefaultBodyLimit::max(LOGIN_BODY_LIMIT)),
        )
        .route(LOGOUT_PATH, get(logout_page).post(logout))
        // Answered by the gate for everyone; never forwarded upstream.
        .route("/robots.txt", get(robots))
        .fallback(proxy_or_login)
        .layer(middleware::from_fn_with_state(state.clone(), record_event))
        .with_state(state))
}

/// Buffer the login form within `request_body_timeout`, so a client that
/// sends headers then stalls can't hold the connection.
async fn login_body_deadline(State(limit): State<Duration>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    match tokio::time::timeout(limit, axum::body::to_bytes(body, LOGIN_BODY_LIMIT)).await {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Ok(Err(e)) => {
            let e = e.into_inner();
            let too_long =
                std::iter::successors(Some(e.as_ref() as &dyn std::error::Error), |s| s.source())
                    .any(|s| s.is::<http_body_util::LengthLimitError>());
            if too_long {
                StatusCode::PAYLOAD_TOO_LARGE.into_response()
            } else {
                StatusCode::BAD_REQUEST.into_response()
            }
        }
        Err(_) => (StatusCode::REQUEST_TIMEOUT, [(header::CONNECTION, "close")]).into_response(),
    }
}

/// Push one event per request, using the `Outcome` the handler attached.
async fn record_event(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_key(req.headers(), peer);
    let (method, m1) = truncate_at(req.method().as_str(), 32);
    let (path, m2) = truncate_at(
        req.uri().path_and_query().map_or("/", |pq| pq.as_str()),
        1024,
    );
    let (user_agent, m3) = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map_or((None, false), |ua| {
            let (t, cut) = truncate_at(ua, 512);
            (Some(t), cut)
        });
    let truncated = m1 || m2 || m3;
    let wsb_path = path.starts_with("/__wsb/");
    let mut resp = next.run(req).await;
    // Axum's own rejections (400/405/413/415/422) carry no Cache-Control;
    // gate answers must never be stored.
    if wsb_path && !resp.headers().contains_key(header::CACHE_CONTROL) {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    let outcome = resp
        .extensions_mut()
        .remove::<Outcome>()
        .unwrap_or(Outcome {
            kind: EventKind::Other,
            user: None,
        });
    state.events.push(Event {
        seq: 0,
        time: String::new(),
        kind: outcome.kind,
        status: resp.status().as_u16(),
        ip,
        method,
        path,
        user: outcome.user,
        user_agent,
        truncated,
    });
    resp
}

/// Static `Disallow: /` for crawlers, served before the session check.
async fn robots() -> Response {
    let mut resp = (axum::http::StatusCode::OK, "User-agent: *\nDisallow: /\n").into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    with_outcome(resp, EventKind::Robots, None)
}

/// Attach what a request did so `record_event` can report it.
pub(crate) fn with_outcome(mut resp: Response, kind: EventKind, user: Option<String>) -> Response {
    resp.extensions_mut().insert(Outcome { kind, user });
    resp
}

fn spawn_purger(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(state.config.limits.purge_interval).await;
            // Reloading drops expired rows and picks up changes made by other
            // processes (a remove-user deletes the user's sessions). Held
            // under session_writes so reloads and session writes stay ordered;
            // the owned guard lives in the closure so it cannot be released
            // while the reload still runs.
            {
                let last = state.session_writes.clone().lock_owned().await;
                let st = state.clone();
                match tokio::task::spawn_blocking(move || {
                    let mut last = last;
                    reload_sessions(&st).map(|max| *last = (*last).max(max))
                })
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("web-safe-block: session reload failed: {e}"),
                    Err(e) => eprintln!("web-safe-block: session reload failed: {e}"),
                }
            }
            let now = Instant::now();
            state.failures.lock().unwrap().retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
                !v.is_empty()
            });
        }
    });
}
