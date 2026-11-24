/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, header};
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
    async fn cached() -> impl IntoResponse {
        (
            AppendHeaders([
                (header::CACHE_CONTROL, "public, max-age=300"),
                (
                    header::HeaderName::from_static("cdn-cache-control"),
                    "max-age=600",
                ),
            ]),
            "cached body",
        )
    }
    // Echo the forwarding headers the gate stamped.
    async fn echo_headers(req: Request) -> String {
        let h = req.headers();
        let get = |n: &str| {
            h.get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        format!("{}|{}", get("x-forwarded-for"), get("x-forwarded-host"))
    }
    // Set-Cookie for wsb_session containing a non-UTF-8 (obs-text) byte.
    async fn raw_cookie() -> impl IntoResponse {
        (
            AppendHeaders([
                (
                    header::SET_COOKIE,
                    HeaderValue::from_bytes(b"wsb_session=evil; a=\xff").unwrap(),
                ),
                (
                    header::SET_COOKIE,
                    HeaderValue::from_static("app=1; Path=/"),
                ),
            ]),
            "raw",
        )
    }
    let app = Router::new()
        .route("/cached", axum::routing::get(cached))
        .route("/headers", axum::routing::get(echo_headers))
        .route("/rawcookie", axum::routing::get(raw_cookie))
        .fallback(any(handler))
        .with_state(hits);
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
    let (addr, monitor_addr, _serve) =
        spawn_proxy_serve(upstream, queue_len, limits, db, std::future::pending()).await;
    (addr, monitor_addr)
}

/// Start the proxy on an existing users.db, serving until `shutdown`
/// resolves; returns (proxy addr, monitor addr, serve task).
async fn spawn_proxy_serve(
    upstream: &str,
    queue_len: usize,
    limits: Limits,
    db: &std::path::Path,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> (SocketAddr, SocketAddr, tokio::task::JoinHandle<()>) {
    let events = Arc::new(EventQueue::new(queue_len));
    let monitor_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let monitor_addr = monitor_listener.local_addr().unwrap();
    monitor::spawn_monitor(
        monitor::MonitorListener::Tcp(monitor_listener),
        events.clone(),
    );
    let config = Config {
        users: Arc::new(UserStore::open(db).unwrap()),
        upstream: upstream.parse().unwrap(),
        front_page_message: "Site Description Here".into(),
        session_ttl: Duration::from_secs(600),
        cookie_secure: false,
        fail_delay: Duration::ZERO,
        limits,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = web_safe_block::build_router(config, events).unwrap();
    let serve = tokio::spawn(async move {
        web_safe_block::serve(listener, router, limits, shutdown)
            .await
            .unwrap()
    });
    (addr, monitor_addr, serve)
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

struct MonitorClient {
    r: BufReader<std::net::TcpStream>,
    /// The `daily_counts` lines the monitor sends on connect, oldest first.
    daily: Vec<serde_json::Value>,
    /// First non-daily line read while draining the daily block.
    pending: Option<serde_json::Value>,
}

impl MonitorClient {
    fn connect(addr: SocketAddr) -> Self {
        let s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut m = MonitorClient {
            r: BufReader::new(s),
            daily: Vec::new(),
            pending: None,
        };
        let mut line = String::new();
        let n = m.r.read_line(&mut line).unwrap();
        assert!(n > 0, "monitor closed");
        let first: serde_json::Value = serde_json::from_str(&line).unwrap();
        if first["kind"] != "daily_counts" {
            // A busy-error line, or (shouldn't happen) a queued event.
            m.pending = Some(first);
            return m;
        }
        m.daily.push(first);
        // The rest of the daily block was already written in one write;
        // anything non-daily means the block ended.
        m.r.get_ref()
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        loop {
            let mut line = String::new();
            match m.r.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                    if v["kind"] == "daily_counts" {
                        m.daily.push(v);
                    } else {
                        m.pending = Some(v);
                        break;
                    }
                }
            }
        }
        m.r.get_ref()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        m
    }

    /// Next line, or None on EOF.
    fn line(&mut self) -> Option<String> {
        if let Some(v) = self.pending.take() {
            return Some(v.to_string());
        }
        let mut line = String::new();
        (self.r.read_line(&mut line).unwrap() > 0).then_some(line)
    }

    fn event(&mut self) -> serde_json::Value {
        if let Some(v) = self.pending.take() {
            return v;
        }
        serde_json::from_str(&self.line().expect("monitor closed")).unwrap()
    }
}

/// Connect once the previous monitor's slot has been released. Also returns
/// the first event if one arrives straight away.
fn connect_when_free(addr: SocketAddr) -> (MonitorClient, Option<serde_json::Value>) {
    for _ in 0..50 {
        let mut m = MonitorClient::connect(addr);
        match m.pending.take() {
            Some(v) if v.to_string().contains("already connected") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            first => return (m, first),
        }
    }
    panic!("monitor slot never freed");
}

/// A client that half-closes (like `nc < /dev/null`) keeps receiving events.
#[tokio::test(flavor = "multi_thread")]
async fn monitor_half_closed_client() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, monitor_addr) = spawn_proxy_with_monitor(&upstream, 10).await;
    let mut m = MonitorClient::connect(monitor_addr);
    m.r.get_ref().shutdown(std::net::Shutdown::Write).unwrap();
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
            .header("sec-fetch-site", "same-origin")
            .body(format!("user=alice&phrase={phrase}&next=%2F"))
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
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, cookie.clone())
        .send()
        .await
        .unwrap();
    check("logout", 303, "/__wsb/logout", Some("alice"));
    let get = |path: &str| client.get(format!("{base}{path}")).send();
    get("/__wsb/nope").await.unwrap();
    check("reserved", 404, "/__wsb/nope", None);
    get("/__wsb/login").await.unwrap();
    check("login_page", 303, "/__wsb/login", None);

    // Reconnect: consumed events are not redelivered.
    drop(m);
    let (mut m, first) = connect_when_free(monitor_addr);
    assert!(first.is_none(), "{first:?}");
    client.get(format!("{base}/after")).send().await.unwrap();
    let e = m.event();
    assert_eq!(e["path"], "/after", "{e}");
    assert_eq!(e["seq"], 13);
}

/// The monitor's opening block is today's counters; queued events follow it.
#[tokio::test(flavor = "multi_thread")]
async fn monitor_daily_counts() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, monitor_addr) = spawn_proxy_with_monitor(&upstream, 100).await;
    let base = format!("http://{proxy}");
    let client = client();

    // An unauthenticated probe on a non-root path, a failed login, a good one.
    client.get(format!("{base}/wp-admin")).send().await.unwrap();
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=wrong&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    login_token(&client, &base).await;

    let mut m = MonitorClient::connect(monitor_addr);
    assert_eq!(m.daily.len(), 1, "{:?}", m.daily);
    let today = &m.daily[0];
    assert_eq!(today["kind"], "daily_counts");
    assert_eq!(today["final"], false);
    let counts = &today["counts"];
    assert_eq!(counts["login_succeeded"], 1);
    assert_eq!(counts["login_failed"], 1);
    assert_eq!(counts["unauth_non_root"], 1);

    // The queued events arrive after the daily block, in order.
    let kinds: Vec<serde_json::Value> = (0..3).map(|_| m.event()["kind"].clone()).collect();
    assert_eq!(
        kinds,
        ["login_page", "login_failed", "login_succeeded"],
        "{kinds:?}"
    );
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
    assert!(body.contains("name=\"user\""), "body: {body}");
    assert!(body.contains("name=\"phrase\""), "body: {body}");
    assert!(body.contains("Submit"));
    assert!(body.contains("/foo?x=1"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // b. wrong phrase -> 401 "Incorrect user name or phrase", no Set-Cookie
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=wrong&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(set_cookie_values(&resp).is_empty());
    let body = resp.text().await.unwrap();
    assert!(body.contains("Incorrect user name or phrase"));

    // b2. correct phrase with the wrong user name -> 401 too
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body("user=carol&phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(set_cookie_values(&resp).is_empty());

    // c. correct phrase (padded) -> 303 + session cookie
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=++CORRECT-HORSE-BATTERY-42++%0A&next=%2Ffoo%3Fx%3D1")
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

    // e2. upstream caching headers are rewritten for shared caches.
    let resp = client
        .get(format!("{base}/cached"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, max-age=300"
    );
    assert!(resp.headers().get("cdn-cache-control").is_none());

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
        .header("sec-fetch-site", "same-origin")
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
            .header("sec-fetch-site", "same-origin")
            .body("user=alice&phrase=wrong&next=%2F")
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
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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
                .header("sec-fetch-site", "same-origin")
                .body("user=alice&phrase=wrong&next=%2F")
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
            .header("sec-fetch-site", "same-origin")
            .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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

// Kept independent of the crate's to_hex so it stays an oracle for the
// cookie_string format stored in the sessions table.
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
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.text().await.unwrap(), "Forbidden");

    // A POST with neither Sec-Fetch-Site nor Origin fails closed: 403.
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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

    // second run: duplicate names (any case) are skipped; a shared phrase is fine
    let out = run_add_user(
        &dir,
        "alice Another Good Phrase 77!\nALICE Another Fine Phrase 88!\ncarol OPENSESAME NUMBER FORTY 4!\ndave Fine But Good Enough 88!\n",
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("user 'alice' already exists"), "{stderr}");
    assert!(stderr.contains("user 'ALICE' already exists"), "{stderr}");
    assert!(stderr.contains("added 2 user(s), skipped 2"), "{stderr}");

    let store = UserStore::open(&dir.join(users::DB_FILE)).unwrap();
    assert!(
        store
            .lookup("admin-bob", "big secret phrase number 99!")
            .unwrap()
            .unwrap()
            .is_admin
    );
    assert!(
        !store
            .lookup("alice", "open sesame number forty 4!")
            .unwrap()
            .unwrap()
            .is_admin
    );
    // carol shares alice's phrase and logs in with it too.
    assert_eq!(
        store
            .lookup("carol", "open sesame number forty 4!")
            .unwrap()
            .unwrap()
            .name,
        "carol"
    );
    assert_eq!(
        store
            .lookup("dave", "fine but good enough 88!")
            .unwrap()
            .unwrap()
            .name,
        "dave"
    );
    assert!(
        store
            .lookup("alice", "another good phrase 77!")
            .unwrap()
            .is_none()
    );
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
    assert!(
        store
            .lookup("alice", "correct-horse-battery-42")
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .lookup("admin-bob", "big secret phrase number 99!")
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
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
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

#[tokio::test(flavor = "multi_thread")]
async fn monitor_truncates_oversized_fields() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, monitor_addr) = spawn_proxy_with_monitor(&upstream, 10).await;
    let mut m = MonitorClient::connect(monitor_addr);
    client()
        .get(format!("http://{proxy}/x"))
        .header(header::USER_AGENT, "a".repeat(100_000))
        .send()
        .await
        .unwrap();
    let e = m.event();
    assert_eq!(e["kind"], "login_page", "{e}");
    assert_eq!(e["user_agent"].as_str().unwrap().len(), 512, "{e}");
    assert_eq!(e["truncated"], true, "{e}");
}

/// Log-out reports failure (and keeps the session) while users.db cannot be
/// written; it succeeds once the write goes through.
#[tokio::test(flavor = "multi_thread")]
async fn logout_waits_for_durable_revoke() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, _, db) = spawn_proxy_full(&upstream, 100, Limits::default()).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    // Hold a write transaction on another connection past the 5s busy timeout.
    let db_path = db.clone();
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let conn = users::open_for_remove(&db_path).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_secs(6));
        conn.execute_batch("ROLLBACK").unwrap();
    });
    locked_rx.recv().unwrap();

    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
    assert!(
        !set_cookie_values(&resp)
            .iter()
            .any(|c| c.contains("Max-Age=0")),
        "cookie must not be cleared on failure"
    );
    assert!(resp.text().await.unwrap().contains("Log out failed"));
    // The session is still valid.
    assert_eq!(token_status(&client, &base, &token).await, 200);

    holder.join().unwrap();
    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(token_status(&client, &base, &token).await, 401);

    // A fresh router ("restart") on the same db: the token stays revoked.
    let (proxy2, _) = spawn_proxy_on_db(&upstream, 100, Limits::default(), &db).await;
    assert_eq!(
        token_status(&client, &format!("http://{proxy2}"), &token).await,
        401
    );
}

/// A session write waiting on a locked database does not delay unrelated
/// authenticated traffic.
#[tokio::test(flavor = "multi_thread")]
async fn session_db_contention_does_not_block_requests() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits).await;
    let (proxy, _, db) = spawn_proxy_full(&upstream, 100, Limits::default()).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    let db_path = db.clone();
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let conn = users::open_for_remove(&db_path).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        conn.execute_batch("COMMIT").unwrap();
    });
    locked_rx.recv().unwrap();

    // A second login waits on the database; an authenticated GET does not.
    let c2 = client.clone();
    let b2 = base.clone();
    let login = tokio::spawn(async move {
        c2.post(format!("{b2}/__wsb/login"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
            .send()
            .await
            .unwrap()
            .status()
    });
    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "GET stalled {:?} behind the login's db wait",
        start.elapsed()
    );
    assert_eq!(login.await.unwrap(), 303);
    holder.join().unwrap();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_ready(client: &reqwest::Client, base: &str) {
    for _ in 0..100 {
        if client.get(base).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("serve did not start listening at {base}");
}

fn spawn_serve(dir: &PathBuf) -> std::process::Child {
    bin()
        .arg("serve")
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// A real process restart preserves the persisted creation order: after a
/// fourth login the oldest session is the one evicted.
#[tokio::test(flavor = "multi_thread")]
async fn restart_keeps_eviction_order() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let dir = config_dir();
    let out = run_add_user(&dir, "alice Correct-Horse-Battery-42\n");
    assert!(out.status.success(), "{out:?}");
    let (port, monitor_port) = (free_port(), free_port());
    let config = dir.join("config.toml");
    edit_config(
        &config,
        "listen_addr",
        &format!("listen_addr = \"127.0.0.1:{port}\""),
    );
    edit_config(
        &config,
        "monitor_addr",
        &format!("monitor_addr = \"127.0.0.1:{monitor_port}\""),
    );
    edit_config(&config, "upstream", &format!("upstream = \"{upstream}\""));
    edit_config(&config, "cookie_secure", "cookie_secure = false");
    let base = format!("http://127.0.0.1:{port}");
    let client = client();

    let mut child = spawn_serve(&dir);
    wait_ready(&client, &base).await;
    let mut tokens = Vec::new();
    for _ in 0..3 {
        tokens.push(login_token(&client, &base).await);
    }
    child.kill().unwrap();
    child.wait().unwrap();

    let conn = users::open_for_remove(&dir.join(users::DB_FILE)).unwrap();
    let created: Vec<i64> = conn
        .prepare("SELECT created FROM sessions ORDER BY created")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(conn);
    assert_eq!(created.len(), 3);
    assert!(
        created[0] < created[1] && created[1] < created[2],
        "created stamps distinct and increasing: {created:?}"
    );

    let mut child = spawn_serve(&dir);
    wait_ready(&client, &base).await;
    tokens.push(login_token(&client, &base).await);
    for (i, token) in tokens.iter().enumerate() {
        assert_eq!(
            token_status(&client, &base, token).await,
            if i == 0 { 401 } else { 200 },
            "token {i}"
        );
    }
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn cli_db_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = config_dir();
    // add-user under a permissive umask still creates a 0600 db.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("umask 022; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_web-safe-block"))
        .arg("add-user")
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
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let db = dir.join(users::DB_FILE);
    assert_eq!(db.metadata().unwrap().permissions().mode() & 0o777, 0o600);

    // A looser existing file warns but is never chmodded.
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = run_add_user(&dir, "bob Another Fine Phrase 77!\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("accessible to other users"), "{stderr}");
    assert!(stderr.contains("mode 0644"), "{stderr}");
    let out = bin().arg("list-users").current_dir(&dir).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("accessible to other users"), "{stderr}");
    assert_eq!(db.metadata().unwrap().permissions().mode() & 0o777, 0o644);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A fake upstream: reads the request, sends headers plus one body byte,
/// then holds the connection without sending more.
fn spawn_stalled_upstream() -> tokio::task::JoinHandle<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut got = Vec::new();
                    // Read until the request headers are complete.
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                        .await;
                    // Hold the connection open without sending more.
                    std::future::pending::<()>().await;
                });
            }
        });
        addr
    })
}

/// An upstream that stalls mid-body is cut off by the idle body timeout.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_upstream_body_times_out() {
    let upstream = spawn_stalled_upstream().await.unwrap();
    let limits = Limits {
        upstream_body_idle_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (proxy, ..) = spawn_proxy_full(&upstream, 100, limits).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "headers arrive immediately");
    assert!(
        resp.bytes().await.is_err(),
        "stalled body fails after the idle timeout"
    );
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
}

/// Only `max_upstream_requests` requests are in flight upstream at once.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_permit_caps_concurrency() {
    let upstream = spawn_stalled_upstream().await.unwrap();
    let limits = Limits {
        max_upstream_requests: 1,
        upstream_body_idle_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (proxy, ..) = spawn_proxy_full(&upstream, 100, limits).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    // First request holds the sole permit until its body times out.
    let (c1, b1, t1) = (client.clone(), base.clone(), token.clone());
    let stalled = tokio::spawn(async move {
        let resp = c1
            .get(format!("{b1}/foo"))
            .header(header::COOKIE, format!("wsb_session={t1}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.bytes().await.is_err());
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = client
        .get(format!("{base}/bar"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    stalled.await.unwrap();
    // The permit was released when the body ended.
    let resp = client
        .get(format!("{base}/bar"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "headers arrive once a permit is free");
}

#[tokio::test]
async fn connection_header_cannot_strip_forwarding() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    // Connection tokens must not remove CF-Connecting-IP or Host before
    // the gate reads them.
    let resp = client
        .get(format!("{base}/headers"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .header(header::CONNECTION, "cf-connecting-ip, host")
        .header("CF-Connecting-IP", "203.0.113.5")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let (xff, xfh) = body.split_once('|').unwrap();
    assert_eq!(xff, "203.0.113.5", "{body}");
    assert!(!xfh.is_empty(), "x-forwarded-host forwarded: {body}");
}

#[tokio::test]
async fn successful_login_does_not_reset_failures() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let db = temp_dir().join(users::DB_FILE);
    let conn = users::open_for_add(&db).unwrap();
    users::add_users(
        &conn,
        "alice Correct-Horse-Battery-42\nbob Another-Good-Phrase-77!\n".as_bytes(),
        &mut Vec::new(),
    )
    .unwrap();
    drop(conn);
    let (proxy, _) = spawn_proxy_on_db(&upstream, 100, Limits::default(), &db).await;
    let base = format!("http://{proxy}");
    let client = client();
    let ip = "203.0.113.42";
    let login = |body: &str| {
        client
            .post(format!("{base}/__wsb/login"))
            .header("CF-Connecting-IP", ip)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .body(body.to_string())
            .send()
    };

    // 9 failures against alice from one IP.
    for _ in 0..9 {
        let resp = login("user=alice&phrase=wrong&next=%2F").await.unwrap();
        assert_eq!(resp.status(), 401);
    }
    // A successful bob login keeps alice's failure count.
    let resp = login("user=bob&phrase=Another-Good-Phrase-77!&next=%2F")
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    // The next failure is the 10th in the window; the one after is 429.
    let resp = login("user=alice&phrase=wrong&next=%2F").await.unwrap();
    assert_eq!(resp.status(), 401);
    let resp = login("user=alice&phrase=wrong&next=%2F").await.unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn multiple_session_cookies() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();
    let t1 = login_token(&client, &base).await;
    let t2 = login_token(&client, &base).await;

    // A stale/unknown cookie shadowing a valid one still authenticates.
    let resp = client
        .get(format!("{base}/foo"))
        .header(
            header::COOKIE,
            format!("wsb_session=deadbeef; wsb_session={t1}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Logout revokes every wsb_session cookie offered.
    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header("sec-fetch-site", "same-origin")
        .header(
            header::COOKIE,
            format!("wsb_session={t1}; wsb_session={t2}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    for t in [&t1, &t2] {
        assert_eq!(token_status(&client, &base, t).await, 401, "{t}");
    }
}

#[tokio::test]
async fn obs_text_session_set_cookie_stripped() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    let resp = client
        .get(format!("{base}/rawcookie"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    for v in resp.headers().get_all(header::SET_COOKIE) {
        assert!(
            !v.as_bytes().starts_with(b"wsb_session"),
            "obs-text wsb_session Set-Cookie forwarded: {v:?}"
        );
    }
}

#[tokio::test]
async fn login_get_redirects_and_body_limit() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();

    // GET on the login path redirects to / with no-store.
    let resp = client
        .get(format!("{base}/__wsb/login"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/");
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    // A login body over 4 KiB is refused before the handler runs, and
    // does not consume a rate-limit attempt.
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(format!("user=alice&phrase=wrong&next={}", "a".repeat(5000)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "axum's own rejection still marked no-store"
    );

    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=Correct-Horse-Battery-42&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
}

/// An obs-text byte in a sibling cookie must not hide `wsb_session`, and
/// logout with such a header really deletes the session row.
#[tokio::test]
async fn obs_text_sibling_cookie_does_not_hide_session() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let (proxy, _, db) = spawn_proxy_full(&upstream, 100, Limits::default()).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    let cookie =
        HeaderValue::from_bytes(&[b"app=\xff; wsb_session=".as_slice(), token.as_bytes()].concat())
            .unwrap();
    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, cookie.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/__wsb/logout"))
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(token_status(&client, &base, &token).await, 401);
    let conn = users::open_for_remove(&db).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0, "session row deleted");
}

/// A client that stops reading must not pin an upstream permit forever:
/// the write-stall timeout closes its connection.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_client_does_not_hold_upstream_permit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Upstream serves a 32 MiB body.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let n = 32 * 1024 * 1024usize;
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").as_bytes())
                    .await;
                let chunk = vec![b'x'; 64 * 1024];
                for _ in 0..n / chunk.len() {
                    if s.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let limits = Limits {
        max_upstream_requests: 1,
        client_write_stall_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let (proxy, ..) = spawn_proxy_full(&upstream, 100, limits).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    // Open a raw connection that requests the big body and reads nothing.
    let mut stalled = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stalled
        .write_all(
            format!(
                "GET /big HTTP/1.1\r\nHost: {proxy}\r\nCookie: wsb_session={token}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    // Poll until the stall timeout frees the connection and the permit.

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let resp = client
            .get(format!("{base}/foo"))
            .header(header::COOKIE, format!("wsb_session={token}"))
            .send()
            .await
            .unwrap();
        if resp.status() == 200 {
            break;
        }
        assert_eq!(resp.status(), 503);
        assert!(std::time::Instant::now() < deadline, "permit never freed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(stalled);
}

/// Unix-socket upstream: echoes Host, X-Forwarded-For, Cookie and path so the
/// test can see exactly what the gate forwarded.
#[cfg(unix)]
async fn spawn_unix_upstream() -> PathBuf {
    async fn echo(req: Request) -> String {
        let h = req.headers();
        let get = |n: &str| {
            h.get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_default();
        format!(
            "{}|{}|{}|{}",
            get("host"),
            get("x-forwarded-for"),
            get("cookie"),
            path
        )
    }
    // Keep the path short: sun_path is limited (~104 bytes on macOS).
    let sock = temp_dir().join("s.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let app = Router::new().fallback(any(echo));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    sock
}

/// An authenticated request to a unix-socket upstream keeps the visitor's
/// Host header, gets X-Forwarded-For, and has wsb_session stripped.
#[cfg(unix)]
#[tokio::test]
async fn unix_upstream_forwards() {
    let sock = spawn_unix_upstream().await;
    let proxy = spawn_proxy(&format!("unix:{}", sock.display())).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    let resp = client
        .get(format!("{base}/some/path?x=1"))
        .header(
            header::COOKIE,
            format!("other=1; wsb_session={token}; more=2"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let parts: Vec<&str> = body.split('|').collect();
    assert_eq!(parts.len(), 4, "body: {body}");
    assert_eq!(parts[0], proxy.to_string(), "visitor Host not forwarded");
    assert!(!parts[1].is_empty(), "no X-Forwarded-For");
    assert_eq!(parts[2], "other=1; more=2", "wsb_session not stripped");
    assert_eq!(parts[3], "/some/path?x=1");
}

/// A unix upstream whose socket does not exist answers 502, like a refused
/// TCP connection.
#[cfg(unix)]
#[tokio::test]
async fn unix_upstream_missing_socket_is_502() {
    let sock = temp_dir().join("missing.sock");
    let proxy = spawn_proxy(&format!("unix:{}", sock.display())).await;
    let base = format!("http://{proxy}");
    let client = client();
    let token = login_token(&client, &base).await;

    let resp = client
        .get(format!("{base}/foo"))
        .header(header::COOKIE, format!("wsb_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
}

/// The configured front_page_message appears above the form on every login
/// page variant.
#[tokio::test]
async fn front_page_message_shown() {
    let upstream = spawn_upstream(Arc::new(AtomicUsize::new(0))).await;
    let proxy = spawn_proxy(&upstream).await;
    let base = format!("http://{proxy}");
    let client = client();

    let resp = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let h = resp.headers();
    assert_eq!(
        h.get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
    let body = resp.text().await.unwrap();
    let front = body.find("<p>Site Description Here</p>").unwrap();
    assert!(front < body.find("<form").unwrap(), "{body}");

    // Non-root paths render per request with their own `next`.
    let resp = client.get(format!("{base}/wp-admin")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<p>Site Description Here</p>"), "{body}");
    assert!(body.contains("name=\"next\" value=\"/wp-admin\""), "{body}");

    // A failed login re-render shows it too.
    let resp = client
        .post(format!("{base}/__wsb/login"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body("user=alice&phrase=wrong&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<p>Site Description Here</p>"), "{body}");
}

/// /robots.txt is answered by the gate for everyone and never forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn robots_txt() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits.clone()).await;
    let (proxy, monitor_addr) = spawn_proxy_with_monitor(&upstream, 10).await;
    let base = format!("http://{proxy}");
    let client = client();

    let check = |resp: reqwest::Response| {
        assert_eq!(resp.status(), 200);
        let h = resp.headers();
        assert_eq!(
            h.get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            h.get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=86400"
        );
        resp
    };

    // Unauthenticated.
    let resp = check(
        client
            .get(format!("{base}/robots.txt"))
            .send()
            .await
            .unwrap(),
    );
    assert_eq!(resp.text().await.unwrap(), "User-agent: *\nDisallow: /\n");

    // Authenticated.
    let token = login_token(&client, &base).await;
    let resp = check(
        client
            .get(format!("{base}/robots.txt"))
            .header(header::COOKIE, format!("wsb_session={token}"))
            .send()
            .await
            .unwrap(),
    );
    assert_eq!(resp.text().await.unwrap(), "User-agent: *\nDisallow: /\n");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "robots.txt never forwarded");

    // Reported as kind "robots", which inflates no daily counter.
    let mut m = MonitorClient::connect(monitor_addr);
    let counts = &m.daily[0]["counts"];
    assert_eq!(counts["other"], 0);
    assert_eq!(counts["unauth_non_root"], 0);
    let kinds: Vec<serde_json::Value> = (0..3).map(|_| m.event()["kind"].clone()).collect();
    assert_eq!(kinds, ["robots", "login_succeeded", "robots"], "{kinds:?}");
}

/// serve under `umask 000` still creates the monitor unix socket with mode
/// 0600, and a client can connect and read it.
#[cfg(unix)]
#[test]
fn cli_unix_monitor_socket() {
    use std::io::BufReader;
    use std::os::unix::fs::PermissionsExt;
    let dir = config_dir();
    let config = dir.join("config.toml");
    let sock = dir.join("m.sock");
    edit_config(
        &config,
        "monitor_addr",
        &format!("monitor_addr = \"unix:{}\"", sock.display()),
    );
    edit_config(
        &config,
        "listen_addr",
        &format!("listen_addr = \"127.0.0.1:{}\"", free_port()),
    );
    assert!(
        run_add_user(&dir, "alice Correct-Horse-Battery-42\n")
            .status
            .success()
    );

    let mut child = Command::new("sh")
        .arg("-c")
        .arg("umask 000; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_web-safe-block"))
        .arg("serve")
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "monitor socket never appeared"
        );
        assert!(child.try_wait().unwrap().is_none(), "serve exited early");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(sock.metadata().unwrap().permissions().mode() & 0o777, 0o600);

    let s = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert!(line.contains("\"daily_counts\""), "{line}");
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn slow_login_body_times_out() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits).await;
    let limits = Limits {
        request_body_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let (proxy, _, _db) = spawn_proxy_full(&upstream, 100, limits).await;
    let mut s = tokio::net::TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        b"POST /__wsb/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nSec-Fetch-Site: same-origin\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
        .await
        .expect("connection not closed within 5s")
        .unwrap();
    let resp = String::from_utf8_lossy(&buf);
    assert!(resp.starts_with("HTTP/1.1 408"), "{resp}");
}

#[tokio::test]
async fn oversized_login_body_413() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits).await;
    let (proxy, _, _db) = spawn_proxy_full(&upstream, 100, Limits::default()).await;
    let mut s = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut req = b"POST /__wsb/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5000\r\nSec-Fetch-Site: same-origin\r\n\r\n".to_vec();
    req.extend(std::iter::repeat_n(b'x', 5000));
    s.write_all(&req).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
}

#[tokio::test]
async fn connection_cap_queues_extra_connections() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits).await;
    let limits = Limits {
        max_connections: 1,
        ..Limits::default()
    };
    let (proxy, _, _db) = spawn_proxy_full(&upstream, 100, limits).await;
    // Connection A holds the only permit without sending anything.
    let a = std::net::TcpStream::connect(proxy).unwrap();
    let got = client()
        .get(format!("http://{proxy}/robots.txt"))
        .timeout(Duration::from_millis(500))
        .send()
        .await;
    assert!(got.unwrap_err().is_timeout());
    drop(a);
    let resp = client()
        .get(format!("http://{proxy}/robots.txt"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn shutdown_drains_with_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_upstream(hits).await;
    let db = user_db();
    // With no connections, shutdown returns promptly.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let (_, _, serve) = spawn_proxy_serve(&upstream, 100, Limits::default(), &db, async move {
        let _ = rx.await;
    })
    .await;
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), serve)
        .await
        .expect("idle shutdown did not finish")
        .unwrap();
    // A stalled request body must not outlive the drain deadline.
    let limits = Limits {
        shutdown_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let (proxy, _, serve) = spawn_proxy_serve(&upstream, 100, limits, &db, async move {
        let _ = rx.await;
    })
    .await;
    let mut s = tokio::net::TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        b"POST /__wsb/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nSec-Fetch-Site: same-origin\r\n\r\n",
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), serve)
        .await
        .expect("serve did not stop within the drain deadline")
        .unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf))
        .await
        .expect("stalled connection was not closed")
        .unwrap();
}
