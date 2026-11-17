//! Forwarding authenticated requests to the protected upstream server.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::app::with_outcome;
use crate::monitor::EventKind;
use crate::sessions::valid_session;
use crate::state::AppState;
use crate::util::{
    client_key, html_response, login_page, sanitize_next, sets_session_cookie, strip_hop_by_hop,
    strip_session_cookie,
};

pub(crate) async fn proxy_or_login(
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

    // Protocol upgrades (e.g. WebSockets) are not supported.
    if req.headers().contains_key(header::UPGRADE) {
        return with_outcome(
            (StatusCode::NOT_IMPLEMENTED, "Not Implemented").into_response(),
            EventKind::Upgrade,
            Some(user),
        );
    }

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
    // The client is untrusted: rebuild forwarding headers from scratch.
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-real-ip",
    ] {
        while headers.remove(name).is_some() {}
    }
    let key = client_key(headers, Some(peer));
    if let Ok(v) = HeaderValue::from_str(&key) {
        headers.insert("x-forwarded-for", v);
    }
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if state.config.cookie_secure {
            "https"
        } else {
            "http"
        }),
    );
    if let Some(host) = headers.get(header::HOST).cloned() {
        headers.insert("x-forwarded-host", host);
    }

    let pending = tokio::time::timeout(
        state.config.limits.upstream_response_timeout,
        state.client.request(req),
    );
    let upstream_resp = match pending.await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => {
            return (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "text/plain")],
                "Bad Gateway",
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                [(header::CONTENT_TYPE, "text/plain")],
                "Gateway Timeout",
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
