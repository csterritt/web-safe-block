/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! `config.toml` loading and the default file written by `write-config`.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::monitor::MonitorAddr;
use crate::upstream::Upstream;

pub const CONFIG_FILE: &str = "config.toml";

pub const DEFAULT_CONFIG: &str = r#"# web-safe-block configuration. Every setting is required.

# sqlite3 users database, managed with `web-safe-block add-user`.
# A relative path is relative to the directory containing this file.
users_db = "users.db"

# Public-facing address (point Cloudflare Tunnel here).
listen_addr = "127.0.0.1:8080"

# Protected server: http://host:port (no path), or unix:/absolute/path.sock.
upstream = "http://127.0.0.1:3000"

# Plain text shown in a paragraph above the sign-in form (HTML is escaped).
front_page_message = "Site Description Here"

# Session lifetime in seconds (180 days, about 6 months).
session_ttl_secs = 15552000

# Add the Secure flag to the session cookie. Set to false only for plain-http
# testing on a non-localhost hostname.
cookie_secure = true

# Local monitor: a loopback address, or unix:/absolute/path.sock (created
# with mode 0600, only this user can connect).
monitor_addr = "127.0.0.1:8081"

# How many unreported events the monitor queue keeps.
monitor_queue_len = 100

# Maximum request-header block size (bytes) accepted on a client connection;
# larger ones get 431 and a closed connection.
max_header_size = 16384

# Maximum per-connection read buffer (bytes); bounds the memory a client can
# pin with large headers. Hyper requires at least 8192.
max_buf_size = 16384

# Maximum client connections served at once; extras wait in the listen
# backlog. Each connection can retain up to max_buf_size of buffer.
max_connections = 100
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    users_db: PathBuf,
    listen_addr: SocketAddr,
    upstream: String,
    front_page_message: String,
    session_ttl_secs: u64,
    cookie_secure: bool,
    monitor_addr: String,
    monitor_queue_len: usize,
    max_header_size: usize,
    max_buf_size: usize,
    max_connections: usize,
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Resolved against the config file's directory.
    pub users_db: PathBuf,
    pub listen_addr: SocketAddr,
    pub upstream: Upstream,
    pub front_page_message: String,
    pub session_ttl_secs: u64,
    pub cookie_secure: bool,
    pub monitor_addr: MonitorAddr,
    pub monitor_queue_len: usize,
    pub max_header_size: usize,
    pub max_buf_size: usize,
    pub max_connections: usize,
}

fn hint(path: &Path) -> String {
    let flag = if path == Path::new(CONFIG_FILE) {
        String::new()
    } else {
        format!(" -c {}", path.display())
    };
    format!("create one with: web-safe-block{flag} write-config")
}

/// Load and validate a config file. Every setting must be present.
pub fn load(path: &Path) -> Result<Settings, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(format!(
                "config file {} not found; {}",
                path.display(),
                hint(path)
            ));
        }
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let raw: RawSettings = toml::from_str(&text)
        .map_err(|e| format!("invalid config file {}: {e}", path.display()))?;
    let bad = |msg: String| format!("invalid config file {}: {msg}", path.display());

    let upstream: Upstream = raw.upstream.parse().map_err(&bad)?;
    let monitor_addr: MonitorAddr = raw.monitor_addr.parse().map_err(&bad)?;
    if raw.users_db.as_os_str().is_empty() {
        return Err(bad("users_db must not be empty".into()));
    }
    if raw.monitor_queue_len == 0 {
        return Err(bad("monitor_queue_len must be at least 1".into()));
    }
    if raw.session_ttl_secs == 0 {
        return Err(bad("session_ttl_secs must be at least 1".into()));
    }
    if raw.max_buf_size < 8192 {
        return Err(bad("max_buf_size must be at least 8192".into()));
    }
    if raw.max_header_size < 1024 {
        return Err(bad("max_header_size must be at least 1024".into()));
    }
    if raw.max_header_size > raw.max_buf_size {
        return Err(bad(format!(
            "max_header_size must be at most max_buf_size ({})",
            raw.max_buf_size
        )));
    }
    if raw.max_connections == 0 {
        return Err(bad("max_connections must be at least 1".into()));
    }
    if raw.session_ttl_secs > 315_360_000 {
        return Err(bad(
            "session_ttl_secs must be at most 315360000 (10 years)".into()
        ));
    }
    let users_db = match path.parent() {
        Some(dir) if raw.users_db.is_relative() => dir.join(&raw.users_db),
        _ => raw.users_db,
    };
    Ok(Settings {
        users_db,
        listen_addr: raw.listen_addr,
        upstream,
        front_page_message: raw.front_page_message,
        session_ttl_secs: raw.session_ttl_secs,
        cookie_secure: raw.cookie_secure,
        monitor_addr,
        monitor_queue_len: raw.monitor_queue_len,
        max_header_size: raw.max_header_size,
        max_buf_size: raw.max_buf_size,
        max_connections: raw.max_connections,
    })
}

/// Write [`DEFAULT_CONFIG`] to `path`, refusing to overwrite an existing file.
pub fn write_default(path: &Path) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => {
                format!("{} already exists; not overwriting it", path.display())
            }
            _ => format!("cannot create {}: {e}", path.display()),
        })?;
    file.write_all(DEFAULT_CONFIG.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wsb-settings-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn load_str(text: &str) -> Result<Settings, String> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = temp_dir(&N.fetch_add(1, Ordering::SeqCst).to_string());
        let path = dir.join(CONFIG_FILE);
        std::fs::write(&path, text).unwrap();
        let r = load(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        r
    }

    fn replace(key: &str, line: &str) -> String {
        DEFAULT_CONFIG
            .lines()
            .map(|l| {
                if l.starts_with(&format!("{key} =")) {
                    line
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn default_config_loads() {
        let dir = temp_dir("default");
        let path = dir.join(CONFIG_FILE);
        write_default(&path).unwrap();
        let s = load(&path).unwrap();
        assert_eq!(s.users_db, dir.join("users.db"));
        assert_eq!(s.listen_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(s.upstream, "http://127.0.0.1:3000".parse().unwrap());
        assert_eq!(s.front_page_message, "Site Description Here");
        assert_eq!(s.session_ttl_secs / 86_400, 180);
        assert!(s.cookie_secure);
        assert_eq!(s.monitor_addr, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(s.monitor_queue_len, 100);
        assert_eq!(s.max_header_size, 16384);
        assert_eq!(s.max_buf_size, 16384);
        assert_eq!(s.max_connections, 100);

        let err = write_default(&path).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file() {
        let err = load(Path::new("/nonexistent/wsb/config.toml")).unwrap_err();
        assert!(err.contains("not found"), "{err}");
        assert!(
            err.contains("-c /nonexistent/wsb/config.toml write-config"),
            "{err}"
        );
        let err = load(Path::new(CONFIG_FILE)).unwrap_err();
        assert!(err.ends_with("web-safe-block write-config"), "{err}");
    }

    #[test]
    fn missing_setting() {
        let err = load_str(&replace("cookie_secure", "")).unwrap_err();
        assert!(err.contains("cookie_secure"), "{err}");
    }

    #[test]
    fn unknown_setting() {
        let err = load_str(&format!("{DEFAULT_CONFIG}\nlisten_port = 1\n")).unwrap_err();
        assert!(err.contains("listen_port"), "{err}");
    }

    #[test]
    fn invalid_values() {
        for (key, line, needle) in [
            ("upstream", "upstream = \"https://x\"", "http://"),
            ("upstream", "upstream = \"not a uri\"", "upstream"),
            (
                "upstream",
                "upstream = \"http://x/app\"",
                "must not have a path or query",
            ),
            (
                "upstream",
                "upstream = \"http://user:pass@127.0.0.1:3000\"",
                "userinfo",
            ),
            ("users_db", "users_db = \"\"", "users_db"),
            (
                "upstream",
                "upstream = \"http://x?a=1\"",
                "must not have a path or query",
            ),
            (
                "monitor_addr",
                "monitor_addr = \"0.0.0.0:8081\"",
                "loopback",
            ),
            (
                "monitor_queue_len",
                "monitor_queue_len = 0",
                "monitor_queue_len",
            ),
            (
                "session_ttl_secs",
                "session_ttl_secs = 0",
                "session_ttl_secs",
            ),
            (
                "session_ttl_secs",
                "session_ttl_secs = 9999999999",
                "10 years",
            ),
            ("listen_addr", "listen_addr = \"localhost\"", "listen_addr"),
            ("cookie_secure", "cookie_secure = \"yes\"", "cookie_secure"),
            ("max_buf_size", "max_buf_size = 8191", "8192"),
            ("max_header_size", "max_header_size = 512", "1024"),
            ("max_header_size", "max_header_size = 32768", "max_buf_size"),
            ("max_connections", "max_connections = 0", "max_connections"),
        ] {
            let err = load_str(&replace(key, line)).unwrap_err();
            assert!(err.contains(needle), "{line}: {err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn upstream_unix_socket() {
        let s = load_str(&replace("upstream", "upstream = \"unix:/run/app.sock\"")).unwrap();
        assert_eq!(
            s.upstream,
            crate::upstream::Upstream::Unix(Path::new("/run/app.sock").into())
        );
        assert_eq!(s.upstream.to_string(), "unix:/run/app.sock");

        for (line, needle) in [
            ("upstream = \"unix:\"", "unix:/absolute/path"),
            ("upstream = \"unix:run/app.sock\"", "absolute"),
            ("upstream = \"unix://run/app.sock\"", "unix:/absolute/path"),
        ] {
            let err = load_str(&replace("upstream", line)).unwrap_err();
            assert!(err.contains(needle), "{line}: {err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn monitor_addr_unix_socket() {
        let s = load_str(&replace(
            "monitor_addr",
            "monitor_addr = \"unix:/run/wsb/monitor.sock\"",
        ))
        .unwrap();
        assert_eq!(
            s.monitor_addr,
            crate::monitor::MonitorAddr::Unix(Path::new("/run/wsb/monitor.sock").into())
        );

        for (line, needle) in [
            ("monitor_addr = \"unix:\"", "unix:/absolute/path"),
            ("monitor_addr = \"unix:rel/x.sock\"", "absolute"),
            ("monitor_addr = \"unix://x\"", "unix:/absolute/path"),
            ("monitor_addr = \"not an addr\"", "monitor_addr"),
        ] {
            let err = load_str(&replace("monitor_addr", line)).unwrap_err();
            assert!(err.contains(needle), "{line}: {err}");
        }
    }

    #[test]
    fn upstream_root_slash_ok() {
        let s = load_str(&replace(
            "upstream",
            "upstream = \"http://127.0.0.1:3000/\"",
        ))
        .unwrap();
        assert_eq!(s.upstream, "http://127.0.0.1:3000/".parse().unwrap());
    }

    #[test]
    fn absolute_users_db_kept() {
        let s = load_str(&replace("users_db", "users_db = \"/var/lib/wsb/users.db\"")).unwrap();
        assert_eq!(s.users_db, Path::new("/var/lib/wsb/users.db"));
    }
}
