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
/// Approximate total bytes the queue may retain (counts included, not just
/// event count): oversized oldest events are dropped first.
const MAX_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Most events handed to the monitor in one write.
const MAX_BATCH: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Unauthenticated request; the login page was shown.
    LoginPage,
    LoginFailed,
    LoginSucceeded,
    /// User lookup failed; the attempt did not count against the rate limit.
    LoginError,
    /// Too many logins were already queued for the Argon2 slot; 503.
    LoginBusy,
    RateLimited,
    /// The log-out form was shown.
    LogoutPage,
    Logout,
    /// The session could not be durably revoked; it remains valid.
    LogoutError,
    /// Cross-site POST to a `/__wsb/` endpoint; rejected unchanged.
    Forbidden,
    /// Authenticated request forwarded upstream.
    Proxied,
    /// Authenticated request asked for a protocol upgrade; refused with 501.
    Upgrade,
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
    /// True if any field was truncated to its size cap.
    pub truncated: bool,
}

/// Cut `s` at `max` bytes, on a char boundary; reports whether it cut.
pub fn truncate_at(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

/// Per-day counters of security-relevant events, serialized in this order.
#[derive(Default, Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Counts {
    login_succeeded: u64,
    login_failed: u64,
    /// Unauthenticated requests (login page shown) for a path other than `/`
    /// outside `/__wsb/` — probes looking for the app.
    unauth_non_root: u64,
    rate_limited: u64,
    login_busy: u64,
    forbidden: u64,
    reserved: u64,
    other: u64,
    login_error: u64,
    logout_error: u64,
    /// Events evicted from the queue while no monitor was connected.
    dropped_unseen: u64,
}

/// One retained day's counters, as sent to the monitor.
#[derive(Debug, Serialize)]
pub(crate) struct DayReport {
    kind: &'static str,
    /// `YYYY-MM-DD`.
    day: String,
    /// RFC 3339 of max(day start, process start): a restart mid-day is
    /// visible because `since` is later than midnight.
    since: String,
    /// True for days that have fully ended.
    r#final: bool,
    counts: Counts,
}

/// In-memory counters for the last 7 UTC days. Pure and clock-free: every
/// method takes `now` as unix seconds.
#[derive(Default)]
struct DailyCounts {
    /// Process start as unix secs (from the queue's clock).
    started: u64,
    /// (UTC day number, counts), consecutive days, at most 7.
    days: VecDeque<(u64, Counts)>,
}

const RETAINED_DAYS: usize = 7;

impl DailyCounts {
    fn new(started: u64) -> Self {
        DailyCounts {
            started,
            days: VecDeque::new(),
        }
    }

    /// Append zero-filled entries for every day after the last one up to
    /// today (never before the start day), then trim to the newest 7.
    fn roll(&mut self, now: u64) {
        let today = now / 86_400;
        let mut next = match self.days.back() {
            Some((d, _)) => d + 1,
            None => self.started / 86_400,
        };
        while next <= today {
            self.days.push_back((next, Counts::default()));
            next += 1;
        }
        while self.days.len() > RETAINED_DAYS {
            self.days.pop_front();
        }
    }

    fn record(&mut self, now: u64, kind: EventKind, path: &str) {
        self.roll(now);
        let Some((_, c)) = self.days.back_mut() else {
            return;
        };
        match kind {
            EventKind::LoginSucceeded => c.login_succeeded += 1,
            EventKind::LoginFailed => c.login_failed += 1,
            EventKind::LoginPage => {
                let p = path.split('?').next().unwrap_or("");
                if p != "/" && !p.starts_with("/__wsb/") {
                    c.unauth_non_root += 1;
                }
            }
            EventKind::RateLimited => c.rate_limited += 1,
            EventKind::LoginBusy => c.login_busy += 1,
            EventKind::Forbidden => c.forbidden += 1,
            EventKind::Reserved => c.reserved += 1,
            EventKind::Other => c.other += 1,
            EventKind::LoginError => c.login_error += 1,
            EventKind::LogoutError => c.logout_error += 1,
            _ => {}
        }
    }

    fn drop_unseen(&mut self, now: u64) {
        self.roll(now);
        if let Some((_, c)) = self.days.back_mut() {
            c.dropped_unseen += 1;
        }
    }

    fn report_for(&self, day: u64, counts: &Counts, today: u64) -> DayReport {
        let day_start = day.saturating_mul(86_400);
        DayReport {
            kind: "daily_counts",
            day: rfc3339(UNIX_EPOCH + Duration::from_secs(day_start))[..10].to_string(),
            since: rfc3339(UNIX_EPOCH + Duration::from_secs(day_start.max(self.started))),
            r#final: day < today,
            counts: counts.clone(),
        }
    }

    /// All retained days, oldest first.
    fn report(&mut self, now: u64) -> Vec<DayReport> {
        self.roll(now);
        let today = now / 86_400;
        self.days
            .iter()
            .map(|(d, c)| self.report_for(*d, c, today))
            .collect()
    }

    /// The report for a specific past day, if still retained.
    fn finished(&mut self, day: u64, now: u64) -> Option<DayReport> {
        self.roll(now);
        let today = now / 86_400;
        if day >= today {
            return None;
        }
        self.days
            .iter()
            .find(|(d, _)| *d == day)
            .map(|(d, c)| self.report_for(*d, c, today))
    }
}

#[derive(Default)]
struct Inner {
    events: VecDeque<Event>,
    /// Approximate retained bytes across `events`.
    bytes: usize,
    next_seq: u64,
    /// Events overwritten while a monitor was connected, not yet reported.
    dropped: u64,
    /// Highest seq handed to the monitor by `pending`; overwriting those is
    /// not a drop since they were already sent.
    sent_up_to: u64,
    monitor_connected: bool,
    daily: DailyCounts,
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub struct EventQueue {
    inner: Mutex<Inner>,
    ready: Condvar,
    capacity: usize,
    /// Unix seconds source; replaceable in tests.
    clock: fn() -> u64,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        Self::build(capacity, unix_secs)
    }

    #[cfg(test)]
    fn with_clock(capacity: usize, clock: fn() -> u64) -> Self {
        Self::build(capacity, clock)
    }

    fn build(capacity: usize, clock: fn() -> u64) -> Self {
        assert!(capacity > 0, "event queue capacity must be at least 1");
        EventQueue {
            inner: Mutex::new(Inner {
                daily: DailyCounts::new(clock()),
                ..Inner::default()
            }),
            ready: Condvar::new(),
            capacity,
            clock,
        }
    }

    /// Add an event, overwriting the oldest unconsumed ones if the queue is
    /// over its count capacity or its total byte budget.
    pub fn push(&self, mut ev: Event) {
        let now = (self.clock)();
        let mut inner = self.inner.lock().unwrap();
        ev.time = rfc3339(SystemTime::now());
        inner.next_seq += 1;
        ev.seq = inner.next_seq;
        inner.daily.record(now, ev.kind, &ev.path);
        inner.events.push_back(ev);
        inner.bytes += event_bytes(inner.events.back().unwrap());
        while !inner.events.is_empty()
            && (inner.events.len() > self.capacity || inner.bytes > MAX_QUEUE_BYTES)
        {
            let old = inner.events.pop_front().unwrap();
            inner.bytes -= event_bytes(&old);
            if inner.monitor_connected {
                if old.seq > inner.sent_up_to {
                    inner.dropped += 1;
                }
            } else {
                inner.daily.drop_unseen(now);
            }
        }
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
        let batch: Vec<Event> = inner.events.iter().take(MAX_BATCH).cloned().collect();
        if let Some(last) = batch.last() {
            inner.sent_up_to = last.seq;
        }
        (batch, dropped)
    }

    /// Remove all events with `seq <= up_to`.
    pub fn mark_consumed(&self, up_to: u64) {
        let mut inner = self.inner.lock().unwrap();
        while inner.events.front().is_some_and(|e| e.seq <= up_to) {
            let ev = inner.events.pop_front().unwrap();
            inner.bytes -= event_bytes(&ev);
        }
    }

    /// The current UTC day number, per this queue's clock.
    fn utc_day(&self) -> u64 {
        (self.clock)() / 86_400
    }

    /// One report per retained day, oldest first.
    fn daily_report(&self) -> Vec<DayReport> {
        let now = (self.clock)();
        self.inner.lock().unwrap().daily.report(now)
    }

    /// The report for a finished day, if still retained.
    fn finished_day(&self, day: u64) -> Option<DayReport> {
        let now = (self.clock)();
        self.inner.lock().unwrap().daily.finished(day, now)
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

/// Rough retained size: string field contents plus a fixed per-event overhead.
fn event_bytes(e: &Event) -> usize {
    128 + e.time.len()
        + e.ip.len()
        + e.method.len()
        + e.path.len()
        + e.user.as_deref().map_or(0, str::len)
        + e.user_agent.as_deref().map_or(0, str::len)
}

/// Run the monitor on its own OS thread. Each accepted client is served on a
/// further thread so a second client can be turned away immediately.
pub fn spawn_monitor(listener: TcpListener, events: Arc<EventQueue>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("wsb-monitor".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    // accept() can fail fast (e.g. fd exhaustion); don't spin.
                    thread::sleep(Duration::from_millis(100));
                    continue;
                };
                if !events.try_connect() {
                    // Nonblocking: a stalled client must not hold the
                    // accept loop (and its slot decision) hostage.
                    let _ = stream.set_nonblocking(true);
                    let _ = stream.write_all(BUSY_MESSAGE);
                    continue;
                }
                let conn_events = events.clone();
                let spawned = thread::Builder::new()
                    .name("wsb-monitor-conn".into())
                    .spawn(move || {
                        // A panic must still free the monitor slot.
                        struct Guard<'a>(&'a EventQueue);
                        impl Drop for Guard<'_> {
                            fn drop(&mut self) {
                                self.0.disconnect();
                            }
                        }
                        let _guard = Guard(&conn_events);
                        let _ = serve_monitor(stream, &conn_events);
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
    // The daily counters go first, before any queued events.
    let mut out = String::new();
    for report in events.daily_report() {
        out.push_str(&serde_json::to_string(&report).map_err(io::Error::other)?);
        out.push('\n');
    }
    stream.write_all(out.as_bytes())?;
    let mut day = events.utc_day();
    // EOF on read only means the client stopped sending (e.g. `nc < /dev/null`
    // half-closes); it may still be listening. Once seen, liveness is checked
    // with heartbeat probes instead.
    let mut half_closed = false;
    // First probe happens at the first idle check after EOF is seen.
    let mut next_probe: Option<Instant> = None;
    loop {
        let (batch, dropped) = events.pending(IDLE_CHECK);
        let mut out = String::new();
        // UTC midnight passed: send each finished day's final counts.
        let today = events.utc_day();
        while day < today {
            if let Some(report) = events.finished_day(day) {
                out.push_str(&serde_json::to_string(&report).map_err(io::Error::other)?);
                out.push('\n');
            }
            day += 1;
        }
        if out.is_empty() && batch.is_empty() && dropped == 0 {
            if !half_closed {
                half_closed = read_eof(&stream)?;
            }
            if half_closed && next_probe.is_none_or(|t| Instant::now() >= t) {
                probe(&mut stream)?;
                next_probe = Some(Instant::now() + HEARTBEAT_INTERVAL);
            }
            continue;
        }
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
/// the connection is gone (a read error or a pending socket error such as a
/// reset). Any input from the client is discarded.
fn read_eof(stream: &TcpStream) -> io::Result<bool> {
    // Linux keeps returning EOF from read after a FIN even once the peer's
    // RST has arrived; the reset is only visible as the pending socket error.
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    stream.set_nonblocking(true)?;
    let mut buf = [0u8; 256];
    // Drain at most this many pending reads, so a chatty client cannot keep
    // the monitor thread from answering events.
    let mut reads = 0;
    let result = loop {
        match (&*stream).read(&mut buf) {
            Ok(0) => break Ok(true),
            Ok(_) => {
                reads += 1;
                if reads >= 64 {
                    break Ok(false);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
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
    use std::io::BufRead;
    use std::sync::atomic::{AtomicU64, Ordering};

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
            truncated: false,
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
    fn truncate_at_cases() {
        assert_eq!(truncate_at("abc", 10), ("abc".to_string(), false));
        assert_eq!(truncate_at("abcdef", 3), ("abc".to_string(), true));
        // Cut backs off to a char boundary.
        let s = "ab\u{1f600}cd"; // emoji is 4 bytes: a(1) b(1) 😀(4) c(1) d(1)
        let (t, cut) = truncate_at(s, 4);
        assert!(cut);
        assert_eq!(t, "ab");
        assert_eq!(truncate_at(s, 6).0, "ab\u{1f600}");
        assert_eq!(truncate_at("", 0), ("".to_string(), false));
    }

    #[test]
    fn evicts_over_byte_budget() {
        let q = EventQueue::new(usize::MAX);
        let big = "x".repeat(1024 * 1024);
        for _ in 0..5 {
            let mut e = ev(&big);
            e.user_agent = Some(big.clone());
            q.push(e);
        }
        // ~2.1 MiB per event: the oldest were evicted to stay under 4 MiB.
        let (batch, _) = q.pending(Duration::ZERO);
        assert_eq!(
            batch.len(),
            1,
            "{:?}",
            batch.iter().map(|e| e.seq).collect::<Vec<_>>()
        );
        assert_eq!(batch[0].seq, 5);
        q.mark_consumed(5);
        for i in 0..4 {
            q.push(ev(&format!("/{i}")));
        }
        let (batch, _) = q.pending(Duration::ZERO);
        assert_eq!(batch.len(), 4, "small events are unaffected");
    }

    #[test]
    fn pending_capped_at_max_batch() {
        let q = EventQueue::new(1000);
        for i in 0..250 {
            q.push(ev(&format!("/{i}")));
        }
        let (b1, _) = q.pending(Duration::ZERO);
        assert_eq!(b1.len(), 100);
        assert_eq!(b1[0].seq, 1);
        q.mark_consumed(b1.last().unwrap().seq);
        let (b2, _) = q.pending(Duration::ZERO);
        assert_eq!(b2.len(), 100);
        assert_eq!(b2[0].seq, 101);
        q.mark_consumed(b2.last().unwrap().seq);
        let (b3, _) = q.pending(Duration::ZERO);
        assert_eq!(b3.len(), 50);
        assert_eq!(b3[0].seq, 201);
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

    const DAY: u64 = 86_400;

    #[test]
    fn daily_counts_each_kind() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        for kind in [
            EventKind::LoginSucceeded,
            EventKind::LoginFailed,
            EventKind::RateLimited,
            EventKind::LoginBusy,
            EventKind::Forbidden,
            EventKind::Reserved,
            EventKind::Other,
            EventKind::LoginError,
            EventKind::LogoutError,
        ] {
            d.record(t0, kind, "/x");
        }
        let c = &d.days.back().unwrap().1;
        assert_eq!(c.login_succeeded, 1);
        assert_eq!(c.login_failed, 1);
        assert_eq!(c.rate_limited, 1);
        assert_eq!(c.login_busy, 1);
        assert_eq!(c.forbidden, 1);
        assert_eq!(c.reserved, 1);
        assert_eq!(c.other, 1);
        assert_eq!(c.login_error, 1);
        assert_eq!(c.logout_error, 1);
    }

    #[test]
    fn daily_counts_unauth_non_root() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        for path in ["/wp-admin", "/a?b"] {
            d.record(t0, EventKind::LoginPage, path);
        }
        for path in ["/", "/?x=1", "/__wsb/login"] {
            d.record(t0, EventKind::LoginPage, path);
        }
        assert_eq!(d.days.back().unwrap().1.unauth_non_root, 2);
    }

    #[test]
    fn daily_counts_ignores_uncounted_kinds() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        for kind in [
            EventKind::Proxied,
            EventKind::Logout,
            EventKind::LogoutPage,
            EventKind::Upgrade,
        ] {
            d.record(t0, kind, "/x");
        }
        d.record(t0, EventKind::LoginPage, "/");
        assert_eq!(d.days.back().unwrap().1, Counts::default());
    }

    #[test]
    fn daily_counts_rolls_at_midnight() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        d.record(20_001 * DAY - 1, EventKind::LoginSucceeded, "/x");
        d.record(20_001 * DAY, EventKind::LoginSucceeded, "/x");
        let reports = d.report(20_001 * DAY + 60);
        assert_eq!(reports.len(), 2);
        assert!(reports[0].r#final);
        assert!(!reports[1].r#final);
        assert_eq!(reports[0].counts.login_succeeded, 1);
        assert_eq!(reports[1].counts.login_succeeded, 1);
        assert_eq!(
            d.finished(20_000, 20_001 * DAY + 60)
                .unwrap()
                .counts
                .login_succeeded,
            1
        );
        assert!(d.finished(20_001, 20_001 * DAY + 60).is_none());
    }

    #[test]
    fn daily_counts_gap_days_zero_filled() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        d.record(t0, EventKind::Forbidden, "/x");
        d.record(20_005 * DAY, EventKind::Forbidden, "/x");
        let reports = d.report(20_005 * DAY + 60);
        assert_eq!(reports.len(), 6);
        for r in &reports[1..5] {
            assert_eq!(r.counts, Counts::default());
        }
        assert_eq!(reports[5].counts.forbidden, 1);
        assert!(reports[..5].iter().all(|r| r.r#final));
    }

    #[test]
    fn daily_counts_trims_to_seven() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        d.record(t0, EventKind::LoginSucceeded, "/x");
        d.record(20_010 * DAY, EventKind::LoginSucceeded, "/x");
        let reports = d.report(20_010 * DAY + 60);
        assert_eq!(reports.len(), 7);
        assert_eq!(reports[0].day, "2024-10-08");
        assert_eq!(reports[6].counts.login_succeeded, 1);
    }

    #[test]
    fn daily_counts_since_is_start_then_midnight() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        d.record(t0, EventKind::Other, "/x");
        let reports = d.report(20_001 * DAY + 60);
        assert!(
            reports[0].since.ends_with("T01:00:00Z"),
            "{}",
            reports[0].since
        );
        assert!(
            reports[1].since.ends_with("T00:00:00Z"),
            "{}",
            reports[1].since
        );
    }

    #[test]
    fn day_report_json_shape() {
        let t0 = 20_000 * DAY + 3600;
        let mut d = DailyCounts::new(t0);
        d.record(t0, EventKind::LoginSucceeded, "/x");
        d.record(20_001 * DAY, EventKind::LoginFailed, "/x");
        let reports = d.report(20_001 * DAY + 60);
        let s = serde_json::to_string(&reports[0]).unwrap();
        assert_eq!(
            s,
            "{\"kind\":\"daily_counts\",\"day\":\"2024-10-04\",\"since\":\"2024-10-04T01:00:00Z\",\"final\":true,\"counts\":{\"login_succeeded\":1,\"login_failed\":0,\"unauth_non_root\":0,\"rate_limited\":0,\"login_busy\":0,\"forbidden\":0,\"reserved\":0,\"other\":0,\"login_error\":0,\"logout_error\":0,\"dropped_unseen\":0}}"
        );
    }

    #[test]
    fn dropped_unseen_counts_only_without_monitor() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn clk() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        NOW.store(20_100 * DAY + 60, Ordering::SeqCst);
        let q = EventQueue::with_clock(2, clk);
        for _ in 0..4 {
            q.push(ev("/x"));
        }
        assert_eq!(q.daily_report()[0].counts.dropped_unseen, 2);
        assert!(q.try_connect());
        for _ in 0..3 {
            q.push(ev("/x"));
        }
        // Queue still holds seqs 3 and 4, so each push evicts one.
        assert_eq!(q.pending(Duration::ZERO).1, 3);
        assert_eq!(q.daily_report()[0].counts.dropped_unseen, 2);
    }

    #[test]
    fn monitor_receives_daily_then_final() {
        use std::io::BufReader;
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn clk() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        NOW.store(20_000 * DAY + 1000, Ordering::SeqCst);
        let q = Arc::new(EventQueue::with_clock(100, clk));
        let mut e = ev("/wp-admin");
        e.kind = EventKind::LoginSucceeded;
        q.push(e);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_monitor(listener, q.clone());
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "daily_counts");
        assert_eq!(v["final"], false);
        assert_eq!(v["counts"]["login_succeeded"], 1);
        // Then the queued event itself.
        line.clear();
        r.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "login_succeeded");
        // Jump the clock past midnight: the finished day's line arrives.
        NOW.store(20_001 * DAY + 10, Ordering::SeqCst);
        line.clear();
        r.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "daily_counts");
        assert_eq!(v["final"], true);
        assert_eq!(v["counts"]["login_succeeded"], 1);
        q.disconnect();
    }
}
