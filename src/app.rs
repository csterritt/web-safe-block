//! Router assembly, per-request event reporting, and state cleanup.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};

use crate::auth::{login, logout, logout_page};
use crate::monitor::{Event, EventKind, EventQueue, Outcome};
use crate::proxy::proxy_or_login;
use crate::rate_limit::RATE_LIMIT_WINDOW;
use crate::sessions::reload_sessions;
use crate::state::{AppState, Config};
use crate::util::{LOGIN_PATH, LOGOUT_PATH, client_key};

/// Build the public-facing router. Every request is reported to `events`.
/// Loads the persisted sessions before serving; errors if users.db cannot
/// be read.
pub fn build_router(config: Config, events: Arc<EventQueue>) -> Result<Router, String> {
    let state = AppState::new(config, events);
    reload_sessions(&state).map_err(|e| format!("cannot load sessions: {e}"))?;
    spawn_purger(state.clone());
    Ok(Router::new()
        .route(LOGIN_PATH, post(login))
        .route(LOGOUT_PATH, get(logout_page).post(logout))
        .fallback(proxy_or_login)
        .layer(middleware::from_fn_with_state(state.clone(), record_event))
        .with_state(state))
}

/// Push one event per request, using the `Outcome` the handler attached.
async fn record_event(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_key(req.headers(), peer);
    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_string();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut resp = next.run(req).await;
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
    });
    resp
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
            // processes (a remove-user deletes the user's sessions).
            if let Err(e) = reload_sessions(&state) {
                eprintln!("web-safe-block: session reload failed: {e}");
            }
            let now = Instant::now();
            state.failures.lock().unwrap().retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
                !v.is_empty()
            });
        }
    });
}
