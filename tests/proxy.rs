use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::http::header;
use axum::response::{AppendHeaders, IntoResponse};
use axum::routing::any;
use tokio::net::TcpListener;
use web_safe_block::Config;

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

async fn spawn_proxy(upstream: &str) -> SocketAddr {
    let config = Config {
        pass_phrase: "hunter2".to_string(),
        upstream: upstream.parse().unwrap(),
        session_ttl: Duration::from_secs(600),
        cookie_secure: false,
        fail_delay: Duration::ZERO,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service =
        web_safe_block::build_router(config).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
    addr
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
        .body("phrase=++hunter2++%0A&next=%2Ffoo%3Fx%3D1")
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

    // f. logout -> 303 + Max-Age=0; token no longer works
    let resp = client
        .get(format!("{base}/__wsb/logout"))
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
        .body("phrase=hunter2&next=%2F")
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
        .body("phrase=hunter2&next=%2F")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
}

#[test]
fn missing_pass_phrase_exits() {
    for value in [None, Some("   ")] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_web-safe-block"));
        cmd.env_remove("PASS_PHRASE");
        if let Some(v) = value {
            cmd.env("PASS_PHRASE", v);
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("PASS_PHRASE"), "stderr: {stderr}");
    }
}
