//! The HTTP accept loop. Each connection is served by hyper http1 with a
//! per-connection header read timeout (slowloris) and a write-stall
//! timeout (a client that stops reading). At most `limits.max_connections`
//! connections are served at once — extras wait in the listen backlog —
//! and on shutdown in-flight connections are drained for up to
//! `limits.shutdown_timeout`, then closed.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tower::{Service, ServiceExt};

use crate::state::Limits;

/// Serve `router` on `listener` until `shutdown` resolves, then drain
/// in-flight connections for up to `limits.shutdown_timeout`. Enforces
/// `limits.header_read_timeout`, `limits.client_write_stall_timeout`, and
/// `limits.max_connections`.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    tokio::pin!(shutdown);
    let mut make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    let graceful = GracefulShutdown::new();
    let conns = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    // Nothing is ever sent: dropping the sender resolves `changed()` in
    // every connection task still alive after the drain deadline.
    let (abort_tx, abort_rx) = tokio::sync::watch::channel(());
    let mut conn_builder = hyper::server::conn::http1::Builder::new();
    conn_builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    loop {
        let permit = tokio::select! {
            permit = conns.clone().acquire_owned() => {
                match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                }
            }
            _ = &mut shutdown => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = &mut shutdown => break,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(_) => {
                // accept() can fail fast (e.g. fd exhaustion); don't spin.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let svc = make_service
            .call(peer)
            .await
            .unwrap_or_else(|e| match e {})
            .map_request(|req: Request<Incoming>| req.map(Body::new));
        let conn = conn_builder.serve_connection(
            TokioIo::new(StallTimeoutIo::new(
                stream,
                limits.client_write_stall_timeout,
            )),
            TowerToHyperService::new(svc),
        );
        let conn = graceful.watch(conn);
        let mut abort = abort_rx.clone();
        // Errors (client disconnects, timeouts) are expected and quiet.
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = conn => {}
                _ = abort.changed() => {}
            }
        });
    }
    drop(listener);
    if tokio::time::timeout(limits.shutdown_timeout, graceful.shutdown())
        .await
        .is_err()
    {
        eprintln!(
            "web-safe-block: shutdown: connections still open after {}s; closing them",
            limits.shutdown_timeout.as_secs()
        );
    }
    drop(abort_tx);
    Ok(())
}

/// A TcpStream wrapper that fails a write, flush, or shutdown with
/// `TimedOut` once it has been pending for `stall`. Reads pass through
/// untouched.
struct StallTimeoutIo {
    inner: TcpStream,
    stall: Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl StallTimeoutIo {
    fn new(inner: TcpStream, stall: Duration) -> Self {
        StallTimeoutIo {
            inner,
            stall,
            sleep: None,
        }
    }

    /// Run one write-side operation; any Ready disarms the stall timer, a
    /// Pending arms it, and the timer firing reports TimedOut.
    fn poll_write_op<T>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        op: impl FnOnce(&mut TcpStream, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let this = self.get_mut();
        match op(&mut this.inner, cx) {
            Poll::Ready(r) => {
                this.sleep = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                if this.sleep.is_none() {
                    this.sleep = Some(Box::pin(tokio::time::sleep(this.stall)));
                }
                match this.sleep.as_mut().unwrap().as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "client write stalled",
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl AsyncRead for StallTimeoutIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for StallTimeoutIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_op(cx, |s, cx| Pin::new(s).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_op(cx, |s, cx| Pin::new(s).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_op(cx, |s, cx| Pin::new(s).poll_shutdown(cx))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_op(cx, |s, cx| Pin::new(s).poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
