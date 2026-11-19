use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::http::header;
use axum::response::{AppendHeaders, IntoResponse};
use axum::routing::any;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use web_safe_block::monitor::{self, EventQueue};
use web_safe_block::users::{self, UserStore};
use web_safe_block::{Config, Limits};

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Dummy upstream: echoes back the Cookie header and path; sets two
/// Set-Cookie headers, one of which targets `wsb_session`.
async fn spawn_upstream(hits: Arc<AtomicUsize>) -> String {
    async fn handler(
        hits: axum::extract::State<Arc<AtomicUsize>>,
        req: Request,
    ) -> impl IntoResponse {
        hits.fetch_add(1, Ordering::SeqCst);
        let cookie = req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<none>")
            .to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_default();
        (
            AppendHeaders([
                (header::SET_COOKIE, "app=1; Path=/"),
                (header::SET_COOKIE, "wsb_session=evil; Path=/"),
            ]),
            format!("{cookie} {path}"),
        )
    }
    let app = Router::new().fallback(any(handler)).with_state(hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Fresh empty directory under the system temp dir.
fn temp_dir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wsb-it-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fresh users.db containing alice; returns its path.
fn user_db() -> PathBuf {
    let path = temp_dir().join(users::DB_FILE);
    let conn = users::open_for_add(&path).unwrap();
    users::add_users(
        &conn,
        "alice Correct-Horse-Battery-42\n".as_bytes(),
        &mut Vec::new(),
    )
    .unwrap();
    drop(conn);
    path
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_web-safe-block"))
}

async fn spawn_proxy(upstream: &str) -> SocketAddr {
    spawn_proxy_with_monitor(upstream, 100).await.0
}

/// Start the proxy plus a monitor thread; returns (proxy addr, monitor addr).
async fn spawn_proxy_with_monitor(upstream: &str, queue_len: usize) -> (SocketAddr, SocketAddr) {
    let (proxy, monitor, _db) = spawn_proxy_full(upstream, queue_len, Limits::default()).await;
    (proxy, monitor)
}

/// Start the proxy on an existing users.db; returns (proxy addr, monitor addr).
async fn spawn_proxy_on_db(
    upstream: &str,
    queue_len: usize,
    limits: Limits,
    db: &std::path::Path,
) -> (SocketAddr, SocketAddr) {
    let events = Arc::new(EventQueue::new(queue_len));
    let monitor_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let monitor_addr = monitor_listener.local_addr().unwrap();
    monitor::spawn_monitor(monitor_listener, events.clone());
    let config = Config {
        users: Arc::new(UserStore::open(db).unwrap()),
        upstream: upstream.parse().unwrap(),
        session_ttl: Duration::from_secs(600),
        cookie_secure: false,
        fail_delay: Duration::ZERO,
        limits,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = web_safe_block::build_router(config, events)
        .unwrap()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
    (addr, monitor_addr)
}

/// Start the proxy with custom limits on a fresh database;
/// returns (proxy addr, monitor addr, users.db path).
async fn spawn_proxy_full(
    upstream: &str,
    queue_len: usize,
    limits: Limits,
) -> (SocketAddr, SocketAddr, PathBuf) {
    let db = user_db();
    let (addr, monitor_addr) = spawn_proxy_on_db(upstream, queue_len, limits, &db).await;
    (addr, monitor_addr, db)
}

struct MonitorClient(BufReader<std::net::TcpStream>);

impl MonitorClient {
    fn connect(addr: SocketAddr) -> Self {
        let s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        MonitorClient(BufReader::new(s))
    }

    /// Next line, or None on EOF.
    fn line(&mut self) -> Option<String> {
        let mut line = String::new();
        (self.0.read_line(&mut line).unwrap() > 0).then_some(line)
    }

    fn event(&mut self) -> serde_json::Value {
        serde_json::from_str(&self.line().expect("monitor closed")).unwrap()
    }
}

/// Connect once the previous monitor's slot has been released. Also returns
/// the first event if one arrives straight away.
fn connect_when_free(addr: SocketAddr) -> (MonitorClient, Option<serde_json::Value>) {
    for _ in 0..50 {
        let mut m = MonitorClient::connect(addr);
        m.0.get_ref()
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut line = String::new();
        let first = match m.0.read_line(&mut line) {
            Ok(_) if line.contains("already connected") => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Ok(0) => panic!("monitor closed"),
            Ok(_) => Some(serde_json::from_str(&line).unwrap()),
            // Timed out with nothing to read: we hold the slot.
            Err(_) => None,
        };
        m.0.get_ref()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        return (m, first);
    }
    panic!("monitor slot never freed");
}

/// A client that half-closes (like `nc < /dev/null`) keeps receiving events.
#[tokio::test(flavor = "multi_thread")]
async fn monitor_half_closed_client() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, monitor_addr) = spawn_proxy_with_monitor(&upstream, 10).await;
    let mut m = MonitorClient::connect(monitor_addr);
    m.0.get_ref().shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(m.event()["kind"], "heartbeat");
    client()
        .get(format!("http://{proxy}/x"))
        .send()
        .await
        .unwrap();
    let e = m.event();
    assert_eq!(
        (&e["kind"], &e["path"]),
        (&"login_page".into(), &"/x".into())
    );
    let mut second = MonitorClient::connect(monitor_addr);
    assert!(second.line().unwrap().contains("already connected"));

    // After the half-closed client goes away, an event sent to it is not lost
    // and the slot is released without waiting for a heartbeat.
    drop(m);
    client()
        .get(format!("http://{proxy}/y"))
        .send()
        .await
        .unwrap();
    let start = std::time::Instant::now();
    let (_m, first) = connect_when_free(monitor_addr);
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(first.expect("event redelivered")["path"], "/y");
}

#[tokio::test(flavor = "multi_thread")]
async fn monitor_reports() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, monitor_addr) = spawn_proxy_with_monitor(&upstream, 3).await;
    let base = format!("http://{proxy}");
    let client = client();
    let login = |phrase: &str| {
        client
            .post(format!("{base}/__wsb/login"))
            .header("CF-Connecting-IP", "198.51.100.7")
            .header(header::USER_AGENT, "wsb-test")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("phrase={phrase}&next=%2F"))
            .send()
    };

    // No monitor: only the newest 3 of 5 events survive.
    for i in 0..5 {
        client.get(format!("{base}/p{i}")).send().await.unwrap();
    }
    let mut m = MonitorClient::connect(monitor_addr);
    for (seq, path) in [(3, "/p2"), (4, "/p3"), (5, "/p4")] {
        let e = m.event();
        assert_eq!(e["seq"], seq, "{e}");
        assert_eq!(e["path"], path);
        assert_eq!(e["kind"], "login_page");
        assert_eq!(e["status"], 401);
        assert_eq!(e["ip"], "127.0.0.1");
        assert_eq!(e["method"], "GET");
        assert!(e["user"].is_null());
        assert!(e["time"].as_str().unwrap().ends_with('Z'));
    }

    // A second monitor is turned away.
    let mut second = MonitorClient::connect(monitor_addr);
    assert!(second.line().unwrap().contains("already connected"));
    assert!(second.line().is_none());

    // Live events while connected.
    login("wrong").await.unwrap();
    let resp = login("Correct-Horse-Battery-42").await.unwrap();
    let cookie = set_cookie_values(&resp)[0]
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let authed = |path: &str| {
        client
            .get(format!("{base}{path}"))
            .header(header::COOKIE, cookie.clone())
            .send()
    };
    for (i, (kind, status, path, user)) in [
        ("login_failed", 401, "/__wsb/login", None),
        ("login_succeeded", 303, "/__wsb/login", Some("alice")),
    ]
    .into_iter()
    .enumerate()
    {
        let e = m.event();
        assert_eq!(e["seq"], 6 + i, "{e}");
        assert_eq!(e["kind"], kind, "{e}");
        assert_eq!(e["status"], status, "{e}");
        assert_eq!(e["path"], path, "{e}");
        assert_eq!(e["user"].as_str(), user, "{e}");
        assert_eq!(e["ip"], "198.51.100.7", "{e}");
        assert_eq!(e["user_agent"], "wsb-test", "{e}");
    }
    // One request at a time so the 3-slot queue never overflows.
    let mut check = |kind: &str, status: u16, path: &str, user: Option<&str>| {
        let e = m.event();
        assert_eq!(e["kind"], kind, "{e}");
        assert_eq!(e["status"], status, "{e}");
        assert_eq!(e["path"], path, "{e}");
        assert_eq!(e["user"].as_str(), user, "{e}");
    };
    authed("/foo?x=1").await.unwrap();
    check("proxied", 200, "/foo?x=1", Some("alice"));
    authed("/__wsb/logout").await.unwrap();
    check("logout_page", 200, "/__wsb/logout", Some("alice"));
    client
        .post(format!("{base}/__wsb/logout"))
        .header(header::COOKIE, cookie.clone())
        .send()
        .await
        .unwrap();
    check("logout", 303, "/__wsb/logout", Some("alice"));
    let get = |path: &str| client.get(format!("{base}{path}")).send();
    get("/__wsb/nope").await.unwrap();
    check("reserved", 404, "/__wsb/nope", None);
    get("/__wsb/login").await.unwrap();
    check("other", 405, "/__wsb/login", None);

    // Reconnect: consumed events are not redelivered.
    drop(m);
    let (mut m, first) = connect_when_free(monitor_addr);
    assert!(first.is_none(), "{first:?}");
    client.get(format!("{base}/after")).send().await.unwrap();
    let e = m.event();
    assert_eq!(e["path"], "/after", "{e}");
    assert_eq!(e["seq"], 13);
}

fn set_cookie_values(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn end_to_end() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits.clone()).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();

    // a. unauthenticated GET -> 401 login page, upstream untouched
    let resp = client.get(format!("{base}/foo?x=1")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let body = resp.text().await.unwrap();
    assert!(body.contains("name=\"phrase\""), "body: {body}");
    assert!(body.contains("Submit"));
    assert!(body.contains("/foo?x=1"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // b. wrong phrase -> 401 "Incorrect phrase", no Set-Cookie
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=wrong&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(set_cookie_values(&resp).is_empty());
    let body = resp.text().await.unwrap();
    assert!(body.contains("Incorrect phrase"));

    // c. correct phrase (padded) -> 303 + session cookie
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=++CORRECT-HORSE-BATTERY-42++%0A&next=%2Ffoo%3Fx%3D1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/foo?x=1");
    let cookies = set_cookie_values(&resp);
    assert_eq!(cookies.len(), 1, "cookies: {cookies:?}");
    let sc = &cookies[0];
    assert!(sc.starts_with("wsb_session="));
    let token = sc
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("wsb_session=")
        .unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(sc.contains("HttpOnly"));
    assert!(sc.contains("SameSite=Lax"));
    assert!(sc.contains("Path=/"));
    assert!(!sc.contains("Secure"));

    // d. authed GET -> forwarded, wsb_session stripped, evil Set-Cookie dropped
    let resp = client
        .get(format!("{base}/foo"))
        .header(
            header::COOKIE,
            format!("other=1; wsb_session={token}; more=2"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cookies = set_cookie_values(&resp);
    let body = resp.text().await.unwrap();
    assert!(body.contains("other=1; more=2"), "body: {body}");
    assert!(!body.contains("wsb_session"), "body: {body}");
    assert!(
        cookies.iter().any(|c| c.starts_with("app=1")),
        "{cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.contains("wsb_session=evil")),
        "{cookies:?}"
    );

    // e. bogus token -> 401
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, "wsb_session=deadbeef")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body = resp.text().await.unwrap();
    assert!(body.contains("name=\"phrase\""));

    // f. GET logout -> log-out form, session unchanged; POST logs out
    let resp = client
        .get(format!("{base}/__wsb/logout"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Log out"), "body: {body}");
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    let cookies = set_cookie_values(&resp);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].contains("Max-Age=0"));
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn rate_limit() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();
    let ip = "203.0.113.99";

    for _ in 0..10 {
        let resp = client
            .post(format!("{base}/__wsb/login"))
            .header("CF-Connecting-IP", ip)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("phrase=wrong&next=%2F")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }
    // 11th attempt, even with the correct phrase, is rate-limited
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header("CF-Connecting-IP", ip)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Too many attempts"));

    // a different key is unaffected
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header("CF-Connecting-IP", "203.0.113.100")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_is_atomic() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();
    let mut handles = Vec::new();
    for _ in 0..30 {
        let (client, base) = (client.clone(), base.clone());
        handles.push(tokio::spawn(async move {
            client
                .post(format!("{base}/__wsb/login"))
                .header("CF-Connecting-IP", "203.0.113.77")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body("phrase=wrong&next=%2F")
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut counts = (0, 0);
    for h in handles {
        match h.await.unwrap().as_u16() {
            401 => counts.0 += 1,
            429 => counts.1 += 1,
            s => panic!("unexpected status {s}"),
        }
    }
    assert_eq!(counts, (10, 20));
}

#[tokio::test]
async fn per_user_session_cap() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let limits = Limits {
        max_sessions_per_user: 2,
        ..Limits::default()
    };
    let (proxy, ..) = spawn_proxy_full(&upstream, 100, limits).await;
    let base = format!("http://{proxy}");
    let client = client();
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let resp = client
            .post(format!("{base}/__wsb/login"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("phrase=Correct-Horse-Battery-42&next=%2F")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 303);
        let sc = set_cookie_values(&resp)[0].clone();
        tokens.push(
            sc.split(';')
                .next()
                .unwrap()
                .strip_prefix("wsb_session=")
                .unwrap()
                .to_string(),
        );
    }
    for (i, token) in tokens.iter().enumerate() {
        let resp = client
            .get(format!("{base}/foo"))
            .header(header::COOKIE, format!("wsb_session={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            if i == 0 { 401 } else { 200 },
            "{i}"
        );
    }
}

/// POST the login form; returns the raw wsb_session token.
async fn login_token(client: &reqwest::Client, base: &str) -> String {
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    set_cookie_values(&resp)[0]
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("wsb_session=")
        .unwrap()
        .to_string()
}

async fn token_status(client: &reqwest::Client, base: &str, token: &str) -> u16 {
    client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn sessions_survive_restart() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let db = user_db();
    let (proxy, _) = spawn_proxy_on_db(&upstream, 100, Limits::default(), &db).await;
    let client = client();
    let token = login_token(&client, &format!("http://{proxy}")).await;
    assert_eq!(
        token_status(&client, &format!("http://{proxy}"), &token).await,
        200
    );

    // A second router on the same database — a "restart" — accepts the token.
    let (proxy2, _) = spawn_proxy_on_db(&upstream, 100, Limits::default(), &db).await;
    assert_eq!(
        token_status(&client, &format!("http://{proxy2}"), &token).await,
        200
    );
}

#[tokio::test]
async fn fourth_login_evicts_oldest() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, _, db) = spawn_proxy_full(&upstream, 100, Limits::default()).await;
    let base = format!("http://{proxy}");
    let client = client();
    let mut tokens = Vec::new();
    for _ in 0..4 {
        tokens.push(login_token(&client, &base).await);
    }
    for (i, token) in tokens.iter().enumerate() {
        let status = token_status(&client, &base, token).await;
        assert_eq!(status, if i == 0 { 401 } else { 200 }, "token {i}");
    }

    // The table holds the three newest sessions as SHA-256 hashes only.
    let conn = users::open_for_remove(&db).unwrap();
    let mut rows: Vec<(String, String)> = conn
        .prepare("SELECT user_name, cookie_string FROM sessions")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows.sort();
    assert_eq!(rows.len(), 3);
    let hashes: Vec<String> = tokens[1..].iter().map(|t| sha256_hex(t)).collect();
    for (user, cookie) in &rows {
        assert_eq!(user, "alice");
        assert!(hashes.contains(cookie), "{cookie} not a live token hash");
    }
    assert!(!rows.iter().any(|(_, c)| *c == sha256_hex(&tokens[0])));
    // No raw token is ever stored.
    for token in &tokens {
        assert!(!rows.iter().any(|(_, c)| c == token));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_user_invalidates_sessions() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let limits = Limits {
        purge_interval: Duration::from_millis(200),
        ..Limits::default()
    };
    let (proxy, _, db) = spawn_proxy_full(&upstream, 100, limits).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;
    assert_eq!(token_status(&client, &base, &token).await, 200);

    let conn = users::open_for_remove(&db).unwrap();
    assert!(users::remove_user(&conn, "alice").unwrap());
    drop(conn);

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(token_status(&client, &base, &token).await, 401);
    let conn = users::open_for_remove(&db).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_upstream_times_out() {
    // Accept connections but never respond.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let limits = Limits {
        upstream_response_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let (proxy, ..) = spawn_proxy_full(&upstream, 100, limits).await;
    let base = format!("http://{proxy}");
    let client = client();
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    let cookie = set_cookie_values(&resp)[0]
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 504);
    assert_eq!(resp.text().await.unwrap(), "Gateway Timeout");
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn cross_site_posts_rejected() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();

    // Log in to get a session.
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    let cookie = set_cookie_values(&resp)[0]
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Cross-site POST logout: 403, session untouched.
    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header(header::COOKIE, cookie.clone())
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, cookie.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Cross-site POST login via Origin mismatch: 403.
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("origin", "http://evil.example")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.text().await.unwrap(), "Forbidden");

    // Same-site POST logout still works.
    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header(header::COOKIE, cookie.clone())
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
}

fn run_add_user(dir: &PathBuf, input: &str) -> std::process::Output {
    let mut child = bin()
        .arg("add-user")
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn serve_fails_with(dir: &PathBuf, needle: &str) {
    let out = bin().arg("serve").current_dir(dir).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(needle), "stderr: {stderr}");
    assert!(stderr.contains("add-user"), "stderr: {stderr}");
}

/// Fresh temp dir with a default ./config.toml written by `write-config`.
fn config_dir() -> PathBuf {
    let dir = temp_dir();
    let out = bin()
        .arg("write-config")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    dir
}

fn edit_config(path: &PathBuf, key: &str, line: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let text: Vec<&str> = text
        .lines()
        .map(|l| {
            if l.starts_with(&format!("{key} =")) {
                line
            } else {
                l
            }
        })
        .collect();
    std::fs::write(path, text.join("\n")).unwrap();
}

#[test]
fn cli_usage() {
    for args in [
        &[][..],
        &["bogus"][..],
        &["serve", "extra"][..],
        &["-c"][..],
        &["serve", "-c"][..],
        &["-c", "x.toml"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    }
}

#[test]
fn cli_requires_config() {
    let dir = temp_dir();
    for cmd in ["serve", "add-user"] {
        let out = bin().arg(cmd).current_dir(&dir).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{cmd}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("config file config.toml not found"),
            "{stderr}"
        );
        assert!(stderr.contains("web-safe-block write-config"), "{stderr}");
    }
    assert!(!dir.join(users::DB_FILE).exists());

    // A config missing a setting is rejected, naming the setting.
    let out = bin()
        .arg("write-config")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    edit_config(&dir.join("config.toml"), "upstream", "");
    let out = bin().arg("serve").current_dir(&dir).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("upstream"), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_write_config_and_c_flag() {
    let dir = temp_dir();
    std::fs::create_dir(dir.join("sub")).unwrap();
    let write = || {
        bin()
            .args(["-c", "sub/my.toml", "write-config"])
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    assert!(write().status.success());
    let written = std::fs::read_to_string(dir.join("sub/my.toml")).unwrap();
    assert_eq!(written, web_safe_block::settings::DEFAULT_CONFIG);
    assert!(!dir.join("config.toml").exists());

    // Refuses to overwrite.
    std::fs::write(dir.join("sub/my.toml"), format!("{written}# mine\n")).unwrap();
    let out = write();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
    assert!(
        std::fs::read_to_string(dir.join("sub/my.toml"))
            .unwrap()
            .ends_with("# mine\n")
    );

    // users_db is relative to the config file's directory.
    let mut child = bin()
        .args(["add-user", "-c", "sub/my.toml"])
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"alice Correct-Horse-Battery-42\n")
        .unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    assert!(dir.join("sub").join(users::DB_FILE).exists());
    assert!(!dir.join(users::DB_FILE).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_serve_requires_users() {
    let dir = config_dir();
    serve_fails_with(&dir, "no users database");
    // add-user with only bad/blank lines creates the db but adds nobody
    let out = run_add_user(&dir, "\nnophrase\n");
    assert!(!out.status.success());
    assert!(dir.join(users::DB_FILE).exists());
    serve_fails_with(&dir, "has no users");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_monitor_must_be_loopback() {
    let dir = config_dir();
    assert!(
        run_add_user(&dir, "alice Correct-Horse-Battery-42\n")
            .status
            .success()
    );
    edit_config(
        &dir.join("config.toml"),
        "monitor_addr",
        "monitor_addr = \"0.0.0.0:0\"",
    );
    let out = bin().arg("serve").current_dir(&dir).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("monitor_addr must be a loopback"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_add_user() {
    let dir = config_dir();
    let out = run_add_user(
        &dir,
        "alice Open Sesame Number Forty 4!\nadmin-bob  Big Secret Phrase Number 99!\n",
    );
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("added 2 user(s), skipped 0"));

    // second run: duplicate name and duplicate (normalized) phrase are skipped
    let out = run_add_user(
        &dir,
        "alice Another Good Phrase 77!\ncarol OPENSESAME NUMBER FORTY 4!\ndave Fine But Good Enough 88!\n",
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("user 'alice' already exists"), "{stderr}");
    assert!(
        stderr.contains("pass phrase for 'carol' is already in use"),
        "{stderr}"
    );
    assert!(stderr.contains("added 1 user(s), skipped 2"), "{stderr}");

    let store = UserStore::open(&dir.join(users::DB_FILE)).unwrap();
    assert!(
        store
            .lookup("big secret phrase number 99!")
            .unwrap()
            .unwrap()
            .is_admin
    );
    assert!(
        !store
            .lookup("open sesame number forty 4!")
            .unwrap()
            .unwrap()
            .is_admin
    );
    assert_eq!(
        store
            .lookup("fine but good enough 88!")
            .unwrap()
            .unwrap()
            .name,
        "dave"
    );
    assert!(store.lookup("another good phrase 77!").unwrap().is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_remove_user() {
    let dir = config_dir();
    let out = run_add_user(
        &dir,
        "alice Correct-Horse-Battery-42\nadmin-bob Big Secret Phrase Number 99!\n",
    );
    assert!(out.status.success(), "{out:?}");

    // Missing name -> usage error; unknown name -> failure.
    let out = bin().arg("remove-user").current_dir(&dir).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = bin()
        .args(["remove-user", "carol"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no user named 'carol'"), "{stderr}");

    // Removing alice leaves bob; alice's phrase no longer resolves.
    let out = bin()
        .args(["remove-user", "alice"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("removed user 'alice'"));
    let store = UserStore::open(&dir.join(users::DB_FILE)).unwrap();
    assert!(store.lookup("correct-horse-battery-42").unwrap().is_none());
    assert!(
        store
            .lookup("big secret phrase number 99!")
            .unwrap()
            .is_some()
    );

    // Removing the last user leaves a database `serve` refuses.
    let out = bin()
        .args(["remove-user", "admin-bob"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    serve_fails_with(&dir, "has no users");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_list_users() {
    let dir = config_dir();

    // No database yet -> error.
    let out = bin().arg("list-users").current_dir(&dir).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no users database"), "{stderr}");

    run_add_user(
        &dir,
        "alice Correct-Horse-Battery-42\nadmin-bob Big Secret Phrase Number 99!\n",
    );
    let out = bin().arg("list-users").current_dir(&dir).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines, ["admin-bob\ttrue", "alice\tfalse"], "{stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn upgrade_requests_get_501() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits.clone()).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();

    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    let cookie = set_cookie_values(&resp)[0]
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Authenticated upgrade attempt -> 501, nothing forwarded upstream.
    let resp = client
        .get(format!("{base}/ws"))
        .header(header::COOKIE, cookie)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
