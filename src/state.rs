/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Runtime configuration and the shared state the handlers use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioExecutor;

use crate::monitor::EventQueue;
use crate::sessions::Session;
use crate::settings::Settings;
#[cfg(unix)]
use crate::upstream::UnixConnector;
use crate::upstream::Upstream;
use crate::users::UserStore;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_sessions: usize,
    pub max_sessions_per_user: usize,
    pub max_failure_keys: usize,
    pub upstream_connect_timeout: Duration,
    pub upstream_response_timeout: Duration,
    /// Upstream response body is dropped if no data arrives for this long.
    pub upstream_body_idle_timeout: Duration,
    /// At most this many requests are sent upstream concurrently.
    pub max_upstream_requests: usize,
    /// How often sessions are reloaded from users.db and stale state purged.
    pub purge_interval: Duration,
    /// At most this many logins wait for the Argon2 hash slot; the rest get 503.
    pub max_login_waiters: usize,
    /// A client connection's header read must complete within this long.
    pub header_read_timeout: Duration,
    /// A write to the client may stall for at most this long.
    pub client_write_stall_timeout: Duration,
    /// The login form body must arrive within this long.
    pub request_body_timeout: Duration,
    /// At most this many client connections are served at once; further
    /// ones wait in the listen backlog.
    pub max_connections: usize,
    /// On shutdown, in-flight connections get this long to finish before
    /// they are closed.
    pub shutdown_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_sessions: 10_000,
            max_sessions_per_user: 3,
            max_failure_keys: 10_000,
            upstream_connect_timeout: Duration::from_secs(10),
            upstream_response_timeout: Duration::from_secs(60),
            upstream_body_idle_timeout: Duration::from_secs(60),
            max_upstream_requests: 256,
            purge_interval: Duration::from_secs(60),
            max_login_waiters: 32,
            header_read_timeout: Duration::from_secs(30),
            client_write_stall_timeout: Duration::from_secs(60),
            request_body_timeout: Duration::from_secs(15),
            max_connections: 1024,
            shutdown_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    /// Users that may log in, looked up by user name and pass phrase.
    pub users: Arc<UserStore>,
    /// Upstream base: an `http://host[:port]` URI or a unix socket path.
    pub upstream: Upstream,
    /// Plain text shown above the sign-in form (HTML is escaped).
    pub front_page_message: String,
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
            front_page_message: settings.front_page_message.clone(),
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
    pub client: UpstreamClient,
    /// Serializes Argon2 hashing so at most one ~12 MiB run happens at a time.
    pub hash_slot: Arc<tokio::sync::Mutex<()>>,
    /// Serializes every session DB mutation and reload; the value is the last
    /// issued `created` stamp so stamps are unique and strictly increasing.
    pub session_writes: Arc<tokio::sync::Mutex<i64>>,
    /// Bounds concurrent upstream requests; held until the body finishes.
    pub upstream_permits: Arc<tokio::sync::Semaphore>,
    /// Bounds how many logins may queue for `hash_slot` at once.
    pub login_waiters: Arc<tokio::sync::Semaphore>,
    /// The `/` login page, rendered once at startup.
    pub root_page: axum::body::Bytes,
}

/// The hyper client used to reach upstream — TCP for `http://`, a unix
/// domain socket for `unix:/path`. Both share the connect timeout.
#[derive(Clone)]
pub(crate) enum UpstreamClient {
    Tcp(Client<HttpConnector, Body>),
    #[cfg(unix)]
    Unix(Client<UnixConnector, Body>),
}

impl UpstreamClient {
    pub(crate) fn request(&self, req: Request<Body>) -> ResponseFuture {
        match self {
            UpstreamClient::Tcp(c) => c.request(req),
            #[cfg(unix)]
            UpstreamClient::Unix(c) => c.request(req),
        }
    }
}

impl AppState {
    pub fn new(config: Config, events: Arc<EventQueue>) -> Self {
        let client = match &config.upstream {
            Upstream::Http(_) => {
                let mut connector = HttpConnector::new();
                connector.set_connect_timeout(Some(config.limits.upstream_connect_timeout));
                UpstreamClient::Tcp(Client::builder(TokioExecutor::new()).build(connector))
            }
            #[cfg(unix)]
            Upstream::Unix(path) => {
                let connector =
                    UnixConnector::new(path.clone(), config.limits.upstream_connect_timeout);
                UpstreamClient::Unix(Client::builder(TokioExecutor::new()).build(connector))
            }
        };
        let max_upstream_requests = config.limits.max_upstream_requests;
        let max_login_waiters = config.limits.max_login_waiters;
        let root_page = crate::util::login_page(&config.front_page_message, None, "/").into();
        AppState {
            config: Arc::new(config),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            failures: Arc::new(Mutex::new(HashMap::new())),
            events,
            client,
            hash_slot: Arc::new(tokio::sync::Mutex::new(())),
            session_writes: Arc::new(tokio::sync::Mutex::new(0)),
            upstream_permits: Arc::new(tokio::sync::Semaphore::new(max_upstream_requests)),
            login_waiters: Arc::new(tokio::sync::Semaphore::new(max_login_waiters)),
            root_page,
        }
    }
}
