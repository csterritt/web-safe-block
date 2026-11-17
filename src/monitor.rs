//! Local-only access reporting.
//!
//! Request handlers push [`Event`]s into a bounded [`EventQueue`] without
//! blocking. A dedicated monitor thread accepts one TCP client at a time on a
//! loopback port and streams unconsumed events to it as JSON lines, marking
//! them consumed once written. When the queue is full the oldest events are
//! overwritten.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

const IDLE_CHECK: Duration = Duration::from_secs(1);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_WAIT: Duration = Duration::from_millis(100);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const BUSY_MESSAGE: &[u8] = b"{\"error\":\"another monitor is already connected\"}\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Unauthenticated request; the login page was shown.
    LoginPage,
    LoginFailed,
    LoginSucceeded,
    /// User lookup failed; the attempt did not count against the rate limit.
    LoginError,
    RateLimited,
    /// The log-out form was shown.
    LogoutPage,
    Logout,
    /// Cross-site POST to a `/__wsb/` endpoint; rejected unchanged.
    Forbidden,
    /// Authenticated request forwarded upstream.
    Proxied,
    /// Request for an unknown path under `/__wsb/`.
    Reserved,
    /// Anything else, e.g. wrong method or malformed login form.
    Other,
}

/// What a handler reports about a request; attached as a response extension.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub kind: EventKind,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Assigned by [`EventQueue::push`].
    pub seq: u64,
    /// UTC RFC 3339 timestamp, assigned by [`EventQueue::push`].
    pub time: String,
    pub kind: EventKind,
    pub status: u16,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub user: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Default)]
struct Inner {
    events: VecDeque<Event>,
    next_seq: u64,
    /// Events overwritten while a monitor was connected, not yet reported.
    dropped: u64,
    /// Highest seq handed to the monitor by `pending`; overwriting those is
    /// not a drop since they were already sent.
    sent_up_to: u64,
    monitor_connected: bool,
}

pub struct EventQueue {
    inner: Mutex<Inner>,
    ready: Condvar,
    capacity: usize,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "event queue capacity must be at least 1");
        EventQueue {
            inner: Mutex::new(Inner::default()),
            ready: Condvar::new(),
            capacity,
        }
    }

    /// Add an event, overwriting the oldest unconsumed one if the queue is full.
    pub fn push(&self, mut ev: Event) {
        ev.time = rfc3339(SystemTime::now());
        let mut inner = self.inner.lock().unwrap();
        inner.next_seq += 1;
        ev.seq = inner.next_seq;
        if inner.events.len() == self.capacity
            && let Some(old) = inner.events.pop_front()
            && inner.monitor_connected
            && old.seq > inner.sent_up_to
        {
            inner.dropped += 1;
        }
        inner.events.push_back(ev);
        drop(inner);
        self.ready.notify_one();
    }

    /// Wait up to `timeout` for unconsumed events. Returns copies of them (they
    /// stay queued until [`mark_consumed`](Self::mark_consumed)) and the number
    /// of events overwritten since the previous call.
    pub fn pending(&self, timeout: Duration) -> (Vec<Event>, u64) {
        let inner = self.inner.lock().unwrap();
        let (mut inner, _) = self
            .ready
            .wait_timeout_while(inner, timeout, |i| i.events.is_empty() && i.dropped == 0)
            .unwrap();
        let dropped = std::mem::take(&mut inner.dropped);
        let batch: Vec<Event> = inner.events.iter().cloned().collect();
        if let Some(last) = batch.last() {
            inner.sent_up_to = last.seq;
        }
        (batch, dropped)
    }

    /// Remove all events with `seq <= up_to`.
    pub fn mark_consumed(&self, up_to: u64) {
        let mut inner = self.inner.lock().unwrap();
        while inner.events.front().is_some_and(|e| e.seq <= up_to) {
            inner.events.pop_front();
        }
    }

    /// Claim the single monitor slot; false if a monitor is already connected.
    fn try_connect(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.monitor_connected {
            return false;
        }
        inner.monitor_connected = true;
        inner.dropped = 0;
        inner.sent_up_to = 0;
        true
    }

    fn disconnect(&self) {
        self.inner.lock().unwrap().monitor_connected = false;
    }
}

/// Run the monitor on its own OS thread. Each accepted client is served on a
/// further thread so a second client can be turned away immediately.
pub fn spawn_monitor(listener: TcpListener, events: Arc<EventQueue>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("wsb-monitor".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                if !events.try_connect() {
                    let _ = stream.write_all(BUSY_MESSAGE);
                    continue;
                }
                let conn_events = events.clone();
                let spawned = thread::Builder::new()
                    .name("wsb-monitor-conn".into())
                    .spawn(move || {
                        let _ = serve_monitor(stream, &conn_events);
                        conn_events.disconnect();
                    });
                if spawned.is_err() {
                    events.disconnect();
                }
            }
        })
        .expect("failed to spawn monitor thread")
}

fn serve_monitor(mut stream: TcpStream, events: &EventQueue) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    // EOF on read only means the client stopped sending (e.g. `nc < /dev/null`
    // half-closes); it may still be listening. Once seen, liveness is checked
    // with heartbeat probes instead.
    let mut half_closed = false;
    // First probe happens at the first idle check after EOF is seen.
    let mut next_probe: Option<Instant> = None;
    loop {
        let (batch, dropped) = events.pending(IDLE_CHECK);
        if batch.is_empty() && dropped == 0 {
            if !half_closed {
                half_closed = read_eof(&stream)?;
            }
            if half_closed && next_probe.is_none_or(|t| Instant::now() >= t) {
                probe(&mut stream)?;
                next_probe = Some(Instant::now() + HEARTBEAT_INTERVAL);
            }
            continue;
        }
        let mut out = String::new();
        if dropped > 0 {
            out.push_str(&serde_json::json!({"kind": "dropped", "count": dropped}).to_string());
            out.push('\n');
        }
        for ev in &batch {
            out.push_str(&serde_json::to_string(ev).map_err(io::Error::other)?);
            out.push('\n');
        }
        stream.write_all(out.as_bytes())?;
        // The write may have gone to a client that has since closed; wait for
        // a possible reset so those events stay queued for the next monitor.
        thread::sleep(PROBE_WAIT);
        half_closed |= read_eof(&stream)?;
        if let Some(last) = batch.last() {
            events.mark_consumed(last.seq);
        }
    }
}

/// Send a heartbeat line. A client that has fully closed answers with a reset,
/// which shows up as a read error shortly after.
fn probe(stream: &mut TcpStream) -> io::Result<()> {
    let line = serde_json::json!({"kind": "heartbeat", "time": rfc3339(SystemTime::now())});
    stream.write_all(format!("{line}\n").as_bytes())?;
    thread::sleep(PROBE_WAIT);
    read_eof(stream).map(|_| ())
}

/// Non-blocking read: Ok(true) at EOF, Ok(false) if nothing is pending, Err if
/// the connection is gone. Any input from the client is discarded.
fn read_eof(stream: &TcpStream) -> io::Result<bool> {
    stream.set_nonblocking(true)?;
    let mut buf = [0u8; 256];
    let result = loop {
        match (&*stream).read(&mut buf) {
            Ok(0) => break Ok(true),
            Ok(_) => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(false),
            Err(e) => break Err(e),
        }
    };
    stream.set_nonblocking(false)?;
    result
}

/// Format as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Civil-from-days, H. Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(path: &str) -> Event {
        Event {
            seq: 0,
            time: String::new(),
            kind: EventKind::LoginPage,
            status: 401,
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: path.into(),
            user: None,
            user_agent: None,
        }
    }

    fn seqs(q: &EventQueue) -> Vec<u64> {
        q.pending(Duration::ZERO).0.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn overwrites_oldest_when_full() {
        let q = EventQueue::new(3);
        for i in 0..5 {
            q.push(ev(&format!("/{i}")));
        }
        let (batch, dropped) = q.pending(Duration::ZERO);
        assert_eq!(batch.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4, 5]);
        assert_eq!(batch[0].path, "/2");
        assert_eq!(dropped, 0, "drops without a monitor are not reported");
    }

    #[test]
    fn reports_drops_while_connected() {
        let q = EventQueue::new(2);
        assert!(q.try_connect());
        for _ in 0..5 {
            q.push(ev("/"));
        }
        assert_eq!(q.pending(Duration::ZERO).1, 3);
        assert_eq!(q.pending(Duration::ZERO).1, 0);
        // Seqs 4 and 5 were handed out above; overwriting them is not a drop.
        q.push(ev("/"));
        q.push(ev("/"));
        assert_eq!(q.pending(Duration::ZERO).1, 0);
        q.push(ev("/"));
        assert_eq!(q.pending(Duration::ZERO).1, 0);
        // Seq 7 was handed out but seq 8 was not.
        q.push(ev("/"));
        q.push(ev("/"));
        q.push(ev("/"));
        assert_eq!(q.pending(Duration::ZERO).1, 1);
    }

    #[test]
    fn mark_consumed_keeps_newer_events() {
        let q = EventQueue::new(10);
        q.push(ev("/a"));
        q.push(ev("/b"));
        let (batch, _) = q.pending(Duration::ZERO);
        q.push(ev("/c"));
        q.mark_consumed(batch.last().unwrap().seq);
        assert_eq!(seqs(&q), [3]);
    }

    #[test]
    fn pending_wakes_on_push() {
        let q = Arc::new(EventQueue::new(10));
        let q2 = q.clone();
        let t = thread::spawn(move || q2.pending(Duration::from_secs(10)).0.len());
        thread::sleep(Duration::from_millis(50));
        q.push(ev("/"));
        assert_eq!(t.join().unwrap(), 1);
    }

    #[test]
    fn single_monitor_slot() {
        let q = EventQueue::new(1);
        assert!(q.try_connect());
        assert!(!q.try_connect());
        q.disconnect();
        assert!(q.try_connect());
    }

    #[test]
    fn rfc3339_cases() {
        let at = |s| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(at(1_798_761_599), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn event_json_shape() {
        let mut e = ev("/x?y=1");
        e.kind = EventKind::LoginSucceeded;
        e.user = Some("alice".into());
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], "login_succeeded");
        assert_eq!(v["user"], "alice");
        assert_eq!(v["path"], "/x?y=1");
        assert!(v["user_agent"].is_null());
    }
}
