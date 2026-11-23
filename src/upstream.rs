//! The `upstream` setting: an `http://host[:port]` URI or, on Unix, a
//! `unix:/absolute/path.sock` domain socket.

use std::fmt;
use std::str::FromStr;

#[cfg(unix)]
use std::future::Future;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::task::{Context, Poll};
#[cfg(unix)]
use std::time::Duration;

use axum::http::Uri;
use axum::http::uri::{Authority, Scheme};

#[cfg(unix)]
use hyper_util::rt::TokioIo;

/// Where authenticated requests are forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    Http(Uri),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl Upstream {
    /// Scheme and authority stamped on the outgoing request URI. For a unix
    /// socket `localhost` is only the connection-pool key — the connector
    /// ignores it and the visitor's Host header is forwarded untouched.
    pub(crate) fn request_base(&self) -> (Scheme, Authority) {
        match self {
            Upstream::Http(uri) => (
                uri.scheme().cloned().unwrap_or(Scheme::HTTP),
                uri.authority()
                    .cloned()
                    .expect("http upstream always has an authority"),
            ),
            #[cfg(unix)]
            Upstream::Unix(_) => (Scheme::HTTP, Authority::from_static("localhost")),
        }
    }
}

impl FromStr for Upstream {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            return unix_upstream(rest).map(Upstream::Unix);
            #[cfg(not(unix))]
            return Err("unix socket upstream is only supported on Unix".into());
        }
        http_upstream(s).map(Upstream::Http)
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::Http(uri) => uri.fmt(f),
            #[cfg(unix)]
            Upstream::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

#[cfg(unix)]
fn unix_upstream(rest: &str) -> Result<PathBuf, String> {
    unix_socket_path("upstream", rest)
}

/// Validate the part after `unix:`: an absolute path with no NUL bytes.
/// `setting` names the config key in error messages.
#[cfg(unix)]
pub(crate) fn unix_socket_path(setting: &str, rest: &str) -> Result<PathBuf, String> {
    if rest.is_empty() {
        return Err(format!(
            "{setting} unix: requires a path: unix:/absolute/path"
        ));
    }
    if rest.starts_with('/') && !rest[1..].starts_with('/') {
        if rest.contains('\0') {
            return Err(format!("{setting} unix path must not contain NUL bytes"));
        }
        return Ok(PathBuf::from(rest));
    }
    if rest.starts_with("//") {
        return Err(format!(
            "{setting} unix socket uses unix:/absolute/path, not unix://{rest}"
        ));
    }
    Err(format!(
        "{setting} unix path must be absolute (unix:/absolute/path), got unix:{rest:?}"
    ))
}

fn http_upstream(s: &str) -> Result<Uri, String> {
    let uri: Uri = s
        .parse()
        .map_err(|_| format!("upstream is not a valid URI: {s:?}"))?;
    if uri.scheme() != Some(&Scheme::HTTP) || uri.authority().is_none() {
        return Err(format!(
            "upstream must be an http:// URI with a host or unix:/path: {s:?}"
        ));
    }
    if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
        return Err(format!(
            "upstream must not contain userinfo (user:pass@): {s:?}"
        ));
    }
    if uri.path_and_query().is_some_and(|pq| pq != "/") {
        return Err(format!("upstream must not have a path or query: {s:?}"));
    }
    Ok(uri)
}

/// A connector that dials the configured unix socket, ignoring the request
/// URI (its authority is only the pool key).
#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct UnixConnector {
    path: Arc<PathBuf>,
    connect_timeout: Duration,
}

#[cfg(unix)]
impl UnixConnector {
    pub(crate) fn new(path: PathBuf, connect_timeout: Duration) -> Self {
        UnixConnector {
            path: Arc::new(path),
            connect_timeout,
        }
    }
}

#[cfg(unix)]
impl tower::Service<Uri> for UnixConnector {
    type Response = TokioIo<tokio::net::UnixStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TokioIo<tokio::net::UnixStream>>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let path = self.path.clone();
        let timeout = self.connect_timeout;
        Box::pin(async move {
            match tokio::time::timeout(timeout, tokio::net::UnixStream::connect(&*path)).await {
                Ok(stream) => stream.map(TokioIo::new),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream unix socket connect timed out",
                )),
            }
        })
    }
}
