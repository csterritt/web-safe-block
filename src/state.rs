//! Runtime configuration and the shared state the handlers use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::monitor::EventQueue;
use crate::sessions::Session;
use crate::settings::Settings;
use crate::users::UserStore;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_sessions: usize,
    pub max_sessions_per_user: usize,
    pub max_failure_keys: usize,
    pub upstream_connect_timeout: Duration,
    pub upstream_response_timeout: Duration,
    /// How often sessions are reloaded from users.db and stale state purged.
    pub purge_interval: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_sessions: 10_000,
            max_sessions_per_user: 3,
            max_failure_keys: 10_000,
            upstream_connect_timeout: Duration::from_secs(10),
            upstream_response_timeout: Duration::from_secs(60),
            purge_interval: Duration::from_secs(60),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    /// Users that may log in, looked up by normalized pass phrase.
    pub users: Arc<UserStore>,
    /// Upstream base URI (http scheme + host + optional port).
    pub upstream: Uri,
    pub session_ttl: Duration,
    /// Emit `Secure` on session cookies.
    pub cookie_secure: bool,
    /// Delay before answering a failed login.
    pub fail_delay: Duration,
    /// Resource bounds for in-memory state and upstream requests.
    pub limits: Limits,
}

impl Config {
    pub fn new(settings: &Settings, users: UserStore) -> Self {
        Config {
            users: Arc::new(users),
            upstream: settings.upstream.clone(),
            session_ttl: Duration::from_secs(settings.session_ttl_secs),
            cookie_secure: settings.cookie_secure,
            fail_delay: Duration::from_secs(1),
            limits: Limits::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub config: Arc<Config>,
    pub sessions: Arc<Mutex<HashMap<String, Session>>>,
    pub failures: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    pub events: Arc<EventQueue>,
    pub client: Client<HttpConnector, Body>,
}

impl AppState {
    pub fn new(config: Config, events: Arc<EventQueue>) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(config.limits.upstream_connect_timeout));
        let client = Client::builder(TokioExecutor::new()).build(connector);
        AppState {
            config: Arc::new(config),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            failures: Arc::new(Mutex::new(HashMap::new())),
            events,
            client,
        }
    }
}
