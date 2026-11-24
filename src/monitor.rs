/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Local-only access reporting.
//!
//! Request handlers push [`Event`]s into a bounded [`EventQueue`] without
//! blocking. A dedicated monitor thread accepts one TCP client at a time on a
//! loopback port and streams unconsumed events to it as JSON lines, marking
//! them consumed once written. When the queue is full the oldest events are
//! overwritten.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::{Path, PathBuf};

use serde::Serialize;

#[cfg(unix)]
use crate::upstream::unix_socket_path;

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
    /// Request for /robots.txt; answered by the gate.
    Robots,
    /// Request for an unknown path under `/__wsb/`.
    Reserved,
    /// Anything else, e.g. wrong method or malformed login form.
    Other,
}

/// Where the monitor listens: a loopback TCP address or a unix socket.
#[derive(Debug, Clone, PartialEq)]
pub enum MonitorAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl FromStr for MonitorAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            return unix_socket_path("monitor_addr", rest).map(MonitorAddr::Unix);
            #[cfg(not(unix))]
            return Err("unix socket monitor_addr is only supported on Unix".into());
        }
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| format!("monitor_addr is not a valid address or unix:/path: {s:?}"))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "monitor_addr must be a loopback address, got {addr}"
            ));
        }
        Ok(MonitorAddr::Tcp(addr))
    }
}

impl fmt::Display for MonitorAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MonitorAddr::Tcp(a) => a.fmt(f),
            #[cfg(unix)]
            MonitorAddr::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

/// A bound monitor listener, TCP or unix socket.
#[derive(Debug)]
pub enum MonitorListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl MonitorListener {
    fn accept(&self) -> io::Result<Box<dyn MonitorStream>> {
        match self {
            MonitorListener::Tcp(l) => l.accept().map(|(s, _)| Box::new(s) as _),
            #[cfg(unix)]
            MonitorListener::Unix(l) => l.accept().map(|(s, _)| Box::new(s) as _),
        }
    }
}

/// The stream operations the monitor loop needs; both TcpStream and
/// UnixStream provide them natively.
trait MonitorStream: Read + Write + Send + 'static {
    fn take_error(&self) -> io::Result<Option<io::Error>>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
}

impl MonitorStream for TcpStream {
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        TcpStream::take_error(self)
    }
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, dur)
    }
}

#[cfg(unix)]
impl MonitorStream for UnixStream {
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        UnixStream::take_error(self)
    }
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        UnixStream::set_nonblocking(self, nonblocking)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, dur)
    }
}

/// Bind the monitor address. A unix socket is created mode 0600 (via a
/// private temp dir + rename, so it is never reachable with looser
/// permissions) inside an existing directory; a stale socket file at the
/// path is replaced, a live one or a non-socket is an error.
pub fn bind_monitor(addr: &MonitorAddr) -> io::Result<MonitorListener> {
    match addr {
        MonitorAddr::Tcp(a) => TcpListener::bind(a).map(MonitorListener::Tcp),
        #[cfg(unix)]
        MonitorAddr::Unix(path) => bind_unix_monitor(path).map(MonitorListener::Unix),
    }
}

#[cfg(unix)]
fn bind_unix_monitor(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};

    let parent = path.parent().unwrap_or(Path::new("/"));
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if !md.file_type().is_socket() {
            return Err(io::Error::new(
                ErrorKind::AddrInUse,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!(
                        "monitor socket {} is in use by another process",
                        path.display()
                    ),
                ));
            }
            // Stale socket left by a previous run: remove it.
            // Only a refused connect proves nobody is listening; anything
            // else (e.g. permission denied) might be a live socket.
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => std::fs::remove_file(path)?,
            Err(e) => return Err(e),
        }
    }
    // Keep the temporary name short: the bound path must fit in sun_path
    // (104 bytes on macOS), so it should not be much longer than `path`.
    let mut attempt = 0;
    let tmp = loop {
        let tmp = parent.join(format!(".w{:x}-{attempt}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&tmp) {
            Ok(()) => break tmp,
            Err(e) if e.kind() == ErrorKind::AlreadyExists && attempt < 15 => attempt += 1,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        let sock = tmp.join("s");
        let listener = UnixListener::bind(&sock)
            .map_err(|e| io::Error::new(e.kind(), format!("binding {}: {e}", sock.display())))?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&sock, path)?;
        Ok(listener)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
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
    /// today, then trim to the newest 7. A forward clock jump never adds
    /// more than 7 days (older entries fall below the retention floor and
    /// are trimmed, so `days` stays consecutive); a step backward before
    /// any event seeds at the earlier of the start day and today. If the
    /// clock went backward while days are already present, nothing is
    /// added — records keep landing in the newest entry until real time
    /// catches up.
    fn roll(&mut self, now: u64) {
        let today = now / 86_400;
        let oldest = today.saturating_sub(RETAINED_DAYS as u64 - 1);
        let mut next = match self.days.back() {
            Some((d, _)) => d + 1,
            None => (self.started / 86_400).min(today),
        }
        .max(oldest);
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
        // A day seeded before the start day by a backward clock step gets
        // its own midnight as `since`, not a time in its future.
        let since = if day == self.started / 86_400 {
            self.started
        } else {
            day_start
        };
        DayReport {
            kind: "daily_counts",
            day: rfc3339(UNIX_EPOCH + Duration::from_secs(day_start))[..10].to_string(),
            since: rfc3339(UNIX_EPOCH + Duration::from_secs(since)),
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
        let mut inner = self.inner.lock().unwrap();
        let now = (self.clock)();
        ev.time = rfc3339(UNIX_EPOCH + Duration::from_secs(now));
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

    /// One report per retained day, oldest first, plus the current UTC
    /// day — both from the same clock sample under the lock.
    fn daily_report(&self) -> (Vec<DayReport>, u64) {
        let mut inner = self.inner.lock().unwrap();
        let now = (self.clock)();
        (inner.daily.report(now), now / 86_400)
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
pub fn spawn_monitor(listener: MonitorListener, events: Arc<EventQueue>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("wsb-monitor".into())
        .spawn(move || {
            loop {
                let stream = listener.accept();
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

fn serve_monitor(mut stream: Box<dyn MonitorStream>, events: &EventQueue) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    // The daily counters go first, before any queued events.
    let mut out = String::new();
    let (reports, mut day) = events.daily_report();
    for report in reports {
        out.push_str(&serde_json::to_string(&report).map_err(io::Error::other)?);
        out.push('\n');
    }
    stream.write_all(out.as_bytes())?;
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
        // A huge forward clock jump only reports the retained window.
        day = day.max(today.saturating_sub(RETAINED_DAYS as u64 - 1));
        while day < today {
            if let Some(report) = events.finished_day(day) {
                out.push_str(&serde_json::to_string(&report).map_err(io::Error::other)?);
                out.push('\n');
            }
            day += 1;
        }
        if out.is_empty() && batch.is_empty() && dropped == 0 {
            if !half_closed {
                half_closed = read_eof(&mut *stream)?;
            }
            if half_closed && next_probe.is_none_or(|t| Instant::now() >= t) {
                probe(&mut *stream)?;
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
        half_closed |= read_eof(&mut *stream)?;
        if let Some(last) = batch.last() {
            events.mark_consumed(last.seq);
        }
    }
}

/// Send a heartbeat line. A client that has fully closed answers with a reset,
/// which shows up as a read error shortly after.
fn probe(stream: &mut dyn MonitorStream) -> io::Result<()> {
    let line = serde_json::json!({"kind": "heartbeat", "time": rfc3339(SystemTime::now())});
    stream.write_all(format!("{line}\n").as_bytes())?;
    thread::sleep(PROBE_WAIT);
    read_eof(stream).map(|_| ())
}

/// Non-blocking read: Ok(true) at EOF, Ok(false) if nothing is pending, Err if
/// the connection is gone (a read error or a pending socket error such as a
/// reset). Any input from the client is discarded.
fn read_eof(stream: &mut dyn MonitorStream) -> io::Result<bool> {
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
        match stream.read(&mut buf) {
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
            EventKind::Robots,
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
        assert_eq!(q.daily_report().0[0].counts.dropped_unseen, 2);
        assert!(q.try_connect());
        for _ in 0..3 {
            q.push(ev("/x"));
        }
        // Queue still holds seqs 3 and 4, so each push evicts one.
        assert_eq!(q.pending(Duration::ZERO).1, 3);
        assert_eq!(q.daily_report().0[0].counts.dropped_unseen, 2);
    }

    #[test]
    fn daily_counts_forward_jump_from_epoch() {
        let mut d = DailyCounts::new(0);
        d.record(20_000 * DAY + 5, EventKind::LoginFailed, "/x");
        assert_eq!(d.days.len(), RETAINED_DAYS);
        for (i, (day, c)) in d.days.iter().enumerate() {
            assert_eq!(*day, 19_994 + i as u64);
            if i == RETAINED_DAYS - 1 {
                continue;
            }
            assert_eq!(*c, Counts::default(), "day {day}");
        }
        assert_eq!(d.days.back().unwrap().1.login_failed, 1);
    }

    #[test]
    fn daily_counts_huge_forward_jump() {
        let mut d = DailyCounts::new(5 * DAY);
        d.record(5 * DAY, EventKind::LoginSucceeded, "/x");
        d.record(1_000_000_000_000 * DAY, EventKind::LoginSucceeded, "/x");
        assert_eq!(d.days.len(), RETAINED_DAYS);
        for (i, (day, _)) in d.days.iter().enumerate() {
            assert_eq!(
                *day,
                1_000_000_000_000 - RETAINED_DAYS as u64 + 1 + i as u64
            );
        }
        assert_eq!(d.days.back().unwrap().1.login_succeeded, 1);
    }

    #[test]
    fn daily_counts_backward_step_before_first_event() {
        let mut d = DailyCounts::new(100 * DAY + 50);
        d.record(99 * DAY + 5, EventKind::LoginFailed, "/x");
        d.drop_unseen(99 * DAY + 6);
        let reports = d.report(99 * DAY + 10);
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(
            r.day,
            rfc3339(UNIX_EPOCH + Duration::from_secs(99 * DAY))[..10]
        );
        // `since` is day 99's midnight, not the (later) process start.
        assert_eq!(r.since, rfc3339(UNIX_EPOCH + Duration::from_secs(99 * DAY)));
        assert!(!r.r#final);
        assert_eq!(r.counts.login_failed, 1);
        assert_eq!(r.counts.dropped_unseen, 1);
    }

    #[test]
    fn push_uses_queue_clock_for_time() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn clk() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        NOW.store(20_000 * DAY + 3600, Ordering::SeqCst);
        let q = EventQueue::with_clock(10, clk);
        q.push(ev("/x"));
        assert_eq!(q.pending(Duration::ZERO).0[0].time, "2024-10-04T01:00:00Z");
    }

    #[test]
    fn daily_report_returns_today() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn clk() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        NOW.store(20_000 * DAY + 3600, Ordering::SeqCst);
        let q = EventQueue::with_clock(10, clk);
        let (_, today) = q.daily_report();
        assert_eq!(today, 20_000);
    }

    #[test]
    fn monitor_survives_huge_clock_jump() {
        use std::io::BufReader;
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn clk() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        NOW.store(20_000 * DAY + 1000, Ordering::SeqCst);
        let q = Arc::new(EventQueue::with_clock(100, clk));
        q.push(ev("/wp-admin"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_monitor(MonitorListener::Tcp(listener), q.clone());
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["kind"],
            "daily_counts"
        );
        line.clear();
        r.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["kind"],
            "login_page"
        );
        // Jump the clock far forward: only the retained window is replayed.
        NOW.store(10_000_000_000 * DAY, Ordering::SeqCst);
        let mut e = ev("/x");
        e.kind = EventKind::LoginSucceeded;
        q.push(e);
        let mut finals = 0;
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            if v["kind"] == "daily_counts" {
                finals += 1;
                assert!(finals <= RETAINED_DAYS);
            } else {
                assert_eq!(v["kind"], "login_succeeded");
                break;
            }
        }
        q.disconnect();
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
        spawn_monitor(MonitorListener::Tcp(listener), q.clone());
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

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::{UnixListener, UnixStream};

        // Short paths: sun_path is limited (~104 bytes on macOS).
        fn sock(name: &str) -> PathBuf {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "wsb-mon-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(name)
        }

        fn unix_addr(path: &Path) -> MonitorAddr {
            format!("unix:{}", path.display()).parse().unwrap()
        }

        #[test]
        fn bind_monitor_creates_private_socket() {
            let path = sock("m.sock");
            let dir = path.parent().unwrap().to_path_buf();
            let listener = bind_monitor(&unix_addr(&path)).unwrap();
            assert!(matches!(listener, MonitorListener::Unix(_)));
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "umask must not widen the socket");
            // No private temp dir left behind.
            let names: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names, [std::ffi::OsString::from("m.sock")], "{names:?}");
            // The renamed listener still accepts.
            UnixStream::connect(&path).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }

        /// The temporary bind path must not push a path that fits in
        /// sun_path (104 bytes on macOS) over the limit.
        #[test]
        fn bind_monitor_long_directory() {
            let base = sock("x").parent().unwrap().to_path_buf();
            let pad = 85usize.saturating_sub(base.as_os_str().len() + 1).max(1);
            let dir = base.join("d".repeat(pad));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("monitor.sock");
            assert!(path.as_os_str().len() < 104, "{}", path.display());
            let _listener = bind_monitor(&unix_addr(&path)).unwrap();
            UnixStream::connect(&path).unwrap();
            std::fs::remove_dir_all(&base).unwrap();
        }

        #[test]
        fn bind_monitor_replaces_stale_socket() {
            let path = sock("m.sock");
            let dir = path.parent().unwrap().to_path_buf();
            {
                let _dead = UnixListener::bind(&path).unwrap();
            }
            assert!(path.exists(), "dropped listener leaves the file");
            let listener = bind_monitor(&unix_addr(&path)).unwrap();
            assert!(matches!(listener, MonitorListener::Unix(_)));
            UnixStream::connect(&path).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn bind_monitor_live_socket_in_use() {
            let path = sock("m.sock");
            let dir = path.parent().unwrap().to_path_buf();
            let _live = UnixListener::bind(&path).unwrap();
            let err = bind_monitor(&unix_addr(&path)).unwrap_err();
            assert!(err.to_string().contains("in use"), "{err}");
            assert!(path.exists(), "live socket left alone");
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn bind_monitor_refuses_regular_file() {
            let path = sock("m.sock");
            let dir = path.parent().unwrap().to_path_buf();
            std::fs::write(&path, b"keep me").unwrap();
            bind_monitor(&unix_addr(&path)).unwrap_err();
            assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn unix_monitor_streams_events() {
            use std::io::BufReader;
            let path = sock("m.sock");
            let dir = path.parent().unwrap().to_path_buf();
            let listener = bind_monitor(&unix_addr(&path)).unwrap();
            let q = Arc::new(EventQueue::new(10));
            spawn_monitor(listener, q.clone());
            let mut e = ev("/x");
            e.kind = EventKind::LoginSucceeded;
            q.push(e);

            let s = UnixStream::connect(&path).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut r = BufReader::new(s);
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["kind"],
                "daily_counts"
            );
            line.clear();
            r.read_line(&mut line).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["kind"],
                "login_succeeded"
            );

            // A second connection is refused with the busy error.
            let s2 = UnixStream::connect(&path).unwrap();
            s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut r2 = BufReader::new(s2);
            line.clear();
            r2.read_line(&mut line).unwrap();
            assert!(line.contains("already connected"), "{line}");
            q.disconnect();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
