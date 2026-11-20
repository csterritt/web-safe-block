//! Forwarding authenticated requests to the protected upstream server.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::Response;
use http_body::Frame;
use tokio::sync::OwnedSemaphorePermit;

use crate::app::with_outcome;
use crate::monitor::EventKind;
use crate::sessions::valid_session;
use crate::state::AppState;
use crate::util::{
    client_key, html_response, login_page, plain_response, rewrite_cache_control, sanitize_next,
    sets_session_cookie, strip_hop_by_hop, strip_session_cookie,
};

pub(crate) async fn proxy_or_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    // Reserved namespace: never forward /__wsb/* upstream.
    if req.uri().path().starts_with("/__wsb/") {
        return with_outcome(
            plain_response(StatusCode::NOT_FOUND, "Not Found"),
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
            plain_response(StatusCode::NOT_IMPLEMENTED, "Not Implemented"),
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
        Err(_) => return plain_response(StatusCode::BAD_GATEWAY, "Bad Gateway"),
    };
    *req.uri_mut() = new_uri;

    // Read client IP and Host before stripping: a client-controlled
    // `Connection` header must not be able to remove them first.
    let headers = req.headers_mut();
    let key = client_key(headers, Some(peer));
    let host = headers.get(header::HOST).cloned();
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
        headers.remove(name);
    }
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
    if let Some(host) = host {
        headers.insert("x-forwarded-host", host);
    }

    // Bound concurrent upstream requests; the permit lives in the response
    // body until it finishes or is dropped.
    let permit = match state.upstream_permits.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return plain_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable");
        }
    };

    let pending = tokio::time::timeout(
        state.config.limits.upstream_response_timeout,
        state.client.request(req),
    );
    let upstream_resp = match pending.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            eprintln!("web-safe-block: upstream request failed: {e}");
            return plain_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
        }
        Err(_) => {
            return plain_response(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout");
        }
    };

    let (mut parts, body) = upstream_resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    rewrite_cache_control(&mut parts.headers);
    let set_cookies: Vec<HeaderValue> = parts
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|v| !sets_session_cookie(v.as_bytes()))
        .cloned()
        .collect();
    parts.headers.remove(header::SET_COOKIE);
    for v in set_cookies {
        parts.headers.append(header::SET_COOKIE, v);
    }
    Response::from_parts(
        parts,
        Body::new(IdleTimeoutBody::new(
            body,
            permit,
            state.config.limits.upstream_body_idle_timeout,
        )),
    )
}

/// An upstream response body that ends with a timeout error if no frame
/// arrives within `idle`. Holds the concurrency permit until dropped.
struct IdleTimeoutBody<B> {
    inner: B,
    _permit: OwnedSemaphorePermit,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
    /// Set once the stream ended (frame None) or timed out: after that the
    /// body reports end-of-stream forever.
    done: bool,
}

impl<B> IdleTimeoutBody<B> {
    fn new(inner: B, permit: OwnedSemaphorePermit, idle: Duration) -> Self {
        IdleTimeoutBody {
            inner,
            _permit: permit,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            done: false,
        }
    }
}

impl<B> http_body::Body for IdleTimeoutBody<B>
where
    B: http_body::Body + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            // A completed stream ends for good; the timer is left alone.
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(frame) => {
                let deadline = tokio::time::Instant::now() + self.idle;
                self.sleep.as_mut().reset(deadline);
                Poll::Ready(frame.map(|r| r.map_err(io::Error::other)))
            }
            Poll::Pending => match self.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.done = true;
                    Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream body idle timeout",
                    ))))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
