//! `config.toml` loading and the default file written by `write-config`.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::http::{Uri, uri::Scheme};
use serde::Deserialize;

pub const CONFIG_FILE: &str = "config.toml";

pub const DEFAULT_CONFIG: &str = r#"# web-safe-block configuration. Every setting is required.

# sqlite3 users database, managed with `web-safe-block add-user`.
# A relative path is relative to the directory containing this file.
users_db = "users.db"

# Public-facing address (point Cloudflare Tunnel here).
listen_addr = "127.0.0.1:8080"

# Protected server; must be http:// with no path.
upstream = "http://127.0.0.1:3000"

# Session lifetime in seconds (180 days, about 6 months).
session_ttl_secs = 15552000

# Add the Secure flag to the session cookie. Set to false only for plain-http
# testing on a non-localhost hostname.
cookie_secure = true

# Local monitor port; must be a loopback address.
monitor_addr = "127.0.0.1:8081"

# How many unreported events the monitor queue keeps.
monitor_queue_len = 100
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    users_db: PathBuf,
    listen_addr: SocketAddr,
    upstream: String,
    session_ttl_secs: u64,
    cookie_secure: bool,
    monitor_addr: SocketAddr,
    monitor_queue_len: usize,
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Resolved against the config file's directory.
    pub users_db: PathBuf,
    pub listen_addr: SocketAddr,
    pub upstream: Uri,
    pub session_ttl_secs: u64,
    pub cookie_secure: bool,
    pub monitor_addr: SocketAddr,
    pub monitor_queue_len: usize,
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

    let upstream: Uri = raw
        .upstream
        .parse()
        .map_err(|_| bad(format!("upstream is not a valid URI: {:?}", raw.upstream)))?;
    if upstream.scheme() != Some(&Scheme::HTTP) || upstream.authority().is_none() {
        return Err(bad(format!(
            "upstream must be an http:// URI with a host: {:?}",
            raw.upstream
        )));
    }
    if upstream.path_and_query().is_some_and(|pq| pq != "/") {
        return Err(bad(format!(
            "upstream must not have a path or query: {:?}",
            raw.upstream
        )));
    }
    if !raw.monitor_addr.ip().is_loopback() {
        return Err(bad(format!(
            "monitor_addr must be a loopback address, got {}",
            raw.monitor_addr
        )));
    }
    if raw.monitor_queue_len == 0 {
        return Err(bad("monitor_queue_len must be at least 1".into()));
    }
    if raw.session_ttl_secs == 0 {
        return Err(bad("session_ttl_secs must be at least 1".into()));
    }
    let users_db = match path.parent() {
        Some(dir) if raw.users_db.is_relative() => dir.join(&raw.users_db),
        _ => raw.users_db,
    };
    Ok(Settings {
        users_db,
        listen_addr: raw.listen_addr,
        upstream,
        session_ttl_secs: raw.session_ttl_secs,
        cookie_secure: raw.cookie_secure,
        monitor_addr: raw.monitor_addr,
        monitor_queue_len: raw.monitor_queue_len,
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
        assert_eq!(s.upstream, "http://127.0.0.1:3000");
        assert_eq!(s.session_ttl_secs / 86_400, 180);
        assert!(s.cookie_secure);
        assert_eq!(s.monitor_addr, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(s.monitor_queue_len, 1000);

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
            ("listen_addr", "listen_addr = \"localhost\"", "listen_addr"),
            ("cookie_secure", "cookie_secure = \"yes\"", "cookie_secure"),
        ] {
            let err = load_str(&replace(key, line)).unwrap_err();
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
        assert_eq!(s.upstream, "http://127.0.0.1:3000/");
    }

    #[test]
    fn absolute_users_db_kept() {
        let s = load_str(&replace("users_db", "users_db = \"/var/lib/wsb/users.db\"")).unwrap();
        assert_eq!(s.users_db, Path::new("/var/lib/wsb/users.db"));
    }
}
