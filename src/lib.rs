use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Form, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header, uri::Scheme};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rand::Rng;
use serde::Deserialize;

pub mod monitor;
pub mod users;
use monitor::{Event, EventKind, EventQueue, Outcome};
use users::UserStore;

pub const SESSION_COOKIE: &str = "wsb_session";
pub const LOGIN_PATH: &str = "/__wsb/login";
pub const LOGOUT_PATH: &str = "/__wsb/logout";

const RATE_LIMIT_MAX_FAILURES: usize = 10;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(15 * 60);
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

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
}

impl Config {
    /// Load config from environment. Returns Err(message) on invalid config.
    pub fn from_env(users: UserStore) -> Result<Self, String> {
        let upstream_raw =
            std::env::var("UPSTREAM").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let upstream: Uri = upstream_raw
            .parse()
            .map_err(|_| format!("UPSTREAM is not a valid URI: {upstream_raw:?}"))?;
        if upstream.scheme() != Some(&Scheme::HTTP) || upstream.authority().is_none() {
            return Err(format!(
                "UPSTREAM must be an http:// URI with a host: {upstream_raw:?}"
            ));
        }
        let session_ttl_secs: u64 = std::env::var("SESSION_TTL_SECS")
            .ok()
            .map(|s| s.parse())
            .transpose()
            .map_err(|_| "SESSION_TTL_SECS is not a valid integer".to_string())?
            .unwrap_or(604_800);
        let cookie_secure =
            !matches!(std::env::var("COOKIE_SECURE"), Ok(v) if v == "false" || v == "0");
        Ok(Config {
            users: Arc::new(users),
            upstream,
            session_ttl: Duration::from_secs(session_ttl_secs),
            cookie_secure,
            fail_delay: Duration::from_secs(1),
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    failures: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    events: Arc<EventQueue>,
    client: Client<HttpConnector, Body>,
}

struct Session {
    expires: Instant,
    user: String,
}

impl AppState {
    pub fn new(config: Config, events: Arc<EventQueue>) -> Self {
        let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        AppState {
            config: Arc::new(config),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            failures: Arc::new(Mutex::new(HashMap::new())),
            events,
            client,
        }
    }
}

/// Build the public-facing router. Every request is reported to `events`.
pub fn build_router(config: Config, events: Arc<EventQueue>) -> Router {
    let state = AppState::new(config, events);
    spawn_purger(state.clone());
    Router::new()
        .route(LOGIN_PATH, post(login))
        .route(LOGOUT_PATH, any(logout))
        .fallback(proxy_or_login)
        .layer(middleware::from_fn_with_state(state.clone(), record_event))
        .with_state(state)
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

fn with_outcome(mut resp: Response, kind: EventKind, user: Option<String>) -> Response {
    resp.extensions_mut().insert(Outcome { kind, user });
    resp
}

fn spawn_purger(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(PURGE_INTERVAL).await;
            let now = Instant::now();
            state
                .sessions
                .lock()
                .unwrap()
                .retain(|_, s| s.expires > now);
            state.failures.lock().unwrap().retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
                !v.is_empty()
            });
        }
    });
}

// ---------- helpers ----------

/// Parse all Cookie headers and return (name, value) pairs in order.
fn parse_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for hv in headers.get_all(header::COOKIE).iter() {
        if let Ok(s) = hv.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((name, value)) = part.split_once('=') {
                    out.push((name.trim().to_string(), value.trim().to_string()));
                }
            }
        }
    }
    out
}

/// Remove `SESSION_COOKIE` from the Cookie header(s), rebuilding a single
/// Cookie header (or removing it entirely if nothing remains).
fn strip_session_cookie(headers: &mut HeaderMap) {
    let remaining: Vec<String> = parse_cookies(headers)
        .into_iter()
        .filter(|(name, _)| name != SESSION_COOKIE)
        .map(|(n, v)| format!("{n}={v}"))
        .collect();
    while headers.remove(header::COOKIE).is_some() {}
    if !remaining.is_empty()
        && let Ok(v) = HeaderValue::from_str(&remaining.join("; "))
    {
        headers.insert(header::COOKIE, v);
    }
}

/// Sanitize a `next` redirect target; falls back to `/`.
fn sanitize_next(next: &str) -> String {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.starts_with("/__wsb/")
        && !next.chars().any(|c| c.is_control());
    if ok {
        next.to_string()
    } else {
        "/".to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            _ => vec![c],
        })
        .collect()
}

/// True if a Set-Cookie header value sets the session cookie.
fn sets_session_cookie(value: &str) -> bool {
    match value.split_once('=') {
        Some((name, _)) => name.trim() == SESSION_COOKIE,
        None => false,
    }
}

fn login_page(message: Option<&str>, next: &str) -> String {
    let msg = message
        .map(|m| format!("<p>{}</p>\n", html_escape(m)))
        .unwrap_or_default();
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Login</title>\n</head>\n<body>\n{msg}<form method=\"post\" action=\"{LOGIN_PATH}\">\n<label for=\"phrase\">Phrase</label>\n<input type=\"password\" id=\"phrase\" name=\"phrase\" autofocus>\n<input type=\"hidden\" name=\"next\" value=\"{}\">\n<button type=\"submit\">Submit</button>\n</form>\n</body>\n</html>\n",
        html_escape(next)
    )
}

fn html_response(status: StatusCode, body: String) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

fn session_cookie_header(token: &str, ttl: Duration, secure: bool) -> String {
    let mut s = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        ttl.as_secs()
    );
    if secure {
        s.push_str("; Secure");
    }
    s
}

fn clear_cookie_header(secure: bool) -> String {
    let mut s = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if secure {
        s.push_str("; Secure");
    }
    s
}

fn client_key(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| peer.map(|a| a.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The user name of a valid, unexpired session, if the request has one.
fn valid_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = parse_cookies(headers)
        .into_iter()
        .find(|(n, _)| n == SESSION_COOKIE)?
        .1;
    let mut sessions = state.sessions.lock().unwrap();
    match sessions.get(&token) {
        Some(s) if s.expires > Instant::now() => Some(s.user.clone()),
        Some(_) => {
            sessions.remove(&token);
            None
        }
        None => None,
    }
}

fn rate_limited(state: &AppState, key: &str) -> bool {
    let now = Instant::now();
    let mut failures = state.failures.lock().unwrap();
    if let Some(v) = failures.get_mut(key) {
        v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
        v.len() >= RATE_LIMIT_MAX_FAILURES
    } else {
        false
    }
}

fn record_failure(state: &AppState, key: &str) {
    let now = Instant::now();
    let mut failures = state.failures.lock().unwrap();
    let v = failures.entry(key.to_string()).or_default();
    v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
    v.push(now);
}

fn clear_failures(state: &AppState, key: &str) {
    state.failures.lock().unwrap().remove(key);
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Remove hop-by-hop headers: `Connection`, the names it lists, and a fixed set.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let mut names: Vec<String> = Vec::new();
    for hv in headers.get_all(header::CONNECTION).iter() {
        if let Ok(s) = hv.to_str() {
            for n in s.split(',') {
                let n = n.trim();
                if !n.is_empty() {
                    names.push(n.to_string());
                }
            }
        }
    }
    names.extend([
        "connection".to_string(),
        "keep-alive".to_string(),
        "proxy-connection".to_string(),
        "te".to_string(),
        "trailer".to_string(),
        "transfer-encoding".to_string(),
        "upgrade".to_string(),
        "proxy-authorization".to_string(),
        "proxy-authenticate".to_string(),
    ]);
    for name in names {
        if let Ok(hn) = name.parse::<header::HeaderName>() {
            while headers.remove(&hn).is_some() {}
        }
    }
}

// ---------- handlers ----------

#[derive(Deserialize)]
struct LoginForm {
    phrase: String,
    #[serde(default)]
    next: String,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let key = client_key(&headers, Some(peer));
    let next = sanitize_next(&form.next);
    if rate_limited(&state, &key) {
        return with_outcome(
            html_response(
                StatusCode::TOO_MANY_REQUESTS,
                login_page(Some("Too many attempts, try again later."), &next),
            ),
            EventKind::RateLimited,
            None,
        );
    }
    if let Some(user) = state.config.users.lookup(&form.phrase) {
        println!("web-safe-block: user '{}' logged in", user.name);
        let token = new_token();
        state.sessions.lock().unwrap().insert(
            token.clone(),
            Session {
                expires: Instant::now() + state.config.session_ttl,
                user: user.name.clone(),
            },
        );
        clear_failures(&state, &key);
        let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
        let h = resp.headers_mut();
        h.insert(header::LOCATION, HeaderValue::from_str(&next).unwrap());
        h.insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&session_cookie_header(
                &token,
                state.config.session_ttl,
                state.config.cookie_secure,
            ))
            .unwrap(),
        );
        with_outcome(resp, EventKind::LoginSucceeded, Some(user.name))
    } else {
        record_failure(&state, &key);
        tokio::time::sleep(state.config.fail_delay).await;
        with_outcome(
            html_response(
                StatusCode::UNAUTHORIZED,
                login_page(Some("Incorrect phrase."), &next),
            ),
            EventKind::LoginFailed,
            None,
        )
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = parse_cookies(&headers)
        .into_iter()
        .find(|(n, _)| n == SESSION_COOKIE)
        .and_then(|(_, token)| state.sessions.lock().unwrap().remove(&token))
        .map(|s| s.user);
    let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, HeaderValue::from_static("/"));
    h.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie_header(state.config.cookie_secure)).unwrap(),
    );
    with_outcome(resp, EventKind::Logout, user)
}

async fn proxy_or_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    // Reserved namespace: never forward /__wsb/* upstream.
    if req.uri().path().starts_with("/__wsb/") {
        return with_outcome(
            (StatusCode::NOT_FOUND, "Not Found").into_response(),
            EventKind::Reserved,
            None,
        );
    }

    let Some(user) = valid_session(&state, req.headers()) else {
        let next = sanitize_next(req.uri().path_and_query().map_or("/", |pq| pq.as_str()));
        return with_outcome(
            html_response(StatusCode::UNAUTHORIZED, login_page(None, &next)),
            EventKind::LoginPage,
            None,
        );
    };

    with_outcome(
        forward(&state, peer, req).await,
        EventKind::Proxied,
        Some(user),
    )
}

async fn forward(state: &AppState, peer: SocketAddr, mut req: Request) -> Response {
    let upstream = &state.config.upstream;
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = upstream.scheme().cloned();
    parts.authority = upstream.authority().cloned();
    let new_uri = match Uri::from_parts(parts) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response(),
    };
    *req.uri_mut() = new_uri;

    let headers = req.headers_mut();
    strip_session_cookie(headers);
    strip_hop_by_hop(headers);

    let key = client_key(headers, Some(peer));
    match headers.get_mut("x-forwarded-for") {
        Some(v) if !v.as_bytes().is_empty() => {
            if let Ok(existing) = v.to_str()
                && let Ok(nv) = HeaderValue::from_str(&format!("{existing}, {key}"))
            {
                *v = nv;
            }
        }
        _ => {
            if let Ok(v) = HeaderValue::from_str(&key) {
                headers.insert("x-forwarded-for", v);
            }
        }
    }
    if !headers.contains_key("x-forwarded-proto") {
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    }
    if let Some(host) = headers.get(header::HOST).cloned() {
        headers.insert("x-forwarded-host", host);
    }

    let upstream_resp = match state.client.request(req).await {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "text/plain")],
                "Bad Gateway",
            )
                .into_response();
        }
    };

    let (mut parts, body) = upstream_resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let set_cookies: Vec<HeaderValue> = parts
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|v| v.to_str().map(|s| !sets_session_cookie(s)).unwrap_or(true))
        .cloned()
        .collect();
    while parts.headers.remove(header::SET_COOKIE).is_some() {}
    for v in set_cookies {
        parts.headers.append(header::SET_COOKIE, v);
    }
    Response::from_parts(parts, Body::new(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookies(vals: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in vals {
            h.append(header::COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn strip_only_cookie() {
        let mut h = headers_with_cookies(&["wsb_session=abc"]);
        strip_session_cookie(&mut h);
        assert!(h.get(header::COOKIE).is_none());
    }

    #[test]
    fn strip_first_cookie() {
        let mut h = headers_with_cookies(&["wsb_session=abc; a=1; b=2"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn strip_middle_cookie() {
        let mut h = headers_with_cookies(&["a=1; wsb_session=abc; b=2"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn strip_last_cookie() {
        let mut h = headers_with_cookies(&["a=1; b=2; wsb_session=abc"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn strip_multiple_cookie_headers() {
        let mut h = headers_with_cookies(&["a=1; wsb_session=abc", "b=2"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn keep_similarly_named_cookie() {
        let mut h = headers_with_cookies(&["wsb_session2=keep; wsb_session=drop"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "wsb_session2=keep");
    }

    #[test]
    fn sanitize_next_cases() {
        assert_eq!(sanitize_next("/a?b=1"), "/a?b=1");
        assert_eq!(sanitize_next("//evil.com"), "/");
        assert_eq!(sanitize_next("/\\evil"), "/");
        assert_eq!(sanitize_next("http://x"), "/");
        assert_eq!(sanitize_next(""), "/");
        assert_eq!(sanitize_next("/__wsb/login"), "/");
        assert_eq!(sanitize_next("/a\nb"), "/");
    }

    #[test]
    fn html_escape_cases() {
        assert_eq!(html_escape("a&<b>\"'c"), "a&amp;&lt;b&gt;&quot;&#39;c");
    }

    #[test]
    fn set_cookie_name_matching() {
        assert!(sets_session_cookie("wsb_session=x; Path=/"));
        assert!(sets_session_cookie(" wsb_session =x"));
        assert!(!sets_session_cookie("wsb_session2=x"));
    }
}
