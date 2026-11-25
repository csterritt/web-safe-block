/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use web_safe_block::monitor::{self, EventQueue};
use web_safe_block::settings::{self, CONFIG_FILE, Settings};
use web_safe_block::users::{self, UserStore};

const USAGE: &str = "usage: web-safe-block [-c path-to-config] <command> [name]

commands:
  write-config      write a config file with default values (refuses to overwrite)
  add-user          read 'user-name pass phrase words...' lines from stdin into the users database
  remove-user NAME  remove NAME from the users database
  list-users        show user_name and is_admin for every user
  serve             run the proxy and the local monitor port

The config file defaults to ./config.toml.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some((config_path, command, name)) = parse_args(args.into_iter()) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match (command.as_str(), name.as_deref()) {
        ("write-config", None) => write_config(&config_path),
        ("add-user", None) => with_settings(&config_path, add_user),
        ("remove-user", Some(name)) => with_settings(&config_path, |s| remove_user(s, name)),
        ("list-users", None) => with_settings(&config_path, list_users),
        ("serve", None) => with_settings(&config_path, serve),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Accepts a command, at most one positional argument, and `-c path` anywhere.
fn parse_args(args: impl Iterator<Item = String>) -> Option<(PathBuf, String, Option<String>)> {
    let (mut config, mut positional) = (None, Vec::new());
    let mut args = args;
    while let Some(arg) = args.next() {
        if arg == "-c" {
            if config.replace(PathBuf::from(args.next()?)).is_some() {
                return None;
            }
        } else {
            positional.push(arg);
        }
    }
    if positional.len() > 2 {
        return None;
    }
    let mut positional = positional.into_iter();
    Some((
        config.unwrap_or_else(|| PathBuf::from(CONFIG_FILE)),
        positional.next()?,
        positional.next(),
    ))
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("web-safe-block: {msg}");
    ExitCode::FAILURE
}

fn with_settings(path: &Path, run: impl FnOnce(Settings) -> ExitCode) -> ExitCode {
    match settings::load(path) {
        Ok(s) => run(s),
        Err(e) => fail(e),
    }
}

fn write_config(path: &Path) -> ExitCode {
    match settings::write_default(path) {
        Ok(()) => {
            eprintln!("web-safe-block: wrote default config to {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn add_user(settings: Settings) -> ExitCode {
    let conn = match users::open_for_add(&settings.users_db) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match users::add_users(&conn, std::io::stdin().lock(), &mut std::io::stderr()) {
        Ok((added, skipped)) => {
            eprintln!("web-safe-block: added {added} user(s), skipped {skipped} line(s)");
            if skipped > 0 {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => fail(format!("database error: {e}")),
    }
}

fn remove_user(settings: Settings, name: &str) -> ExitCode {
    let db = &settings.users_db;
    let conn = match users::open_for_remove(db) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match users::remove_user(&conn, name) {
        Ok(true) => {
            eprintln!(
                "web-safe-block: removed user '{name}'; a running serve drops their sessions within 60 seconds"
            );
            ExitCode::SUCCESS
        }
        Ok(false) => fail(format!("no user named '{name}'")),
        Err(e) => fail(format!("database error: {e}")),
    }
}

fn list_users(settings: Settings) -> ExitCode {
    let conn = match users::open_read_only(&settings.users_db) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match users::list_users(&conn) {
        Ok(users) => {
            for u in users {
                println!("{}\t{}", u.name, u.is_admin);
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!("database error: {e}")),
    }
}

fn serve(settings: Settings) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return fail(format!("cannot start runtime: {e}")),
    };
    let (listen, monitor_addr, queue_len) = (
        settings.listen_addr,
        settings.monitor_addr.clone(),
        settings.monitor_queue_len,
    );
    if !settings.listen_addr.ip().is_loopback() {
        eprintln!(
            "web-safe-block: warning: listen_addr {} is not a loopback address; CF-Connecting-IP is only trusted from loopback peers, so clients reaching it directly are rate-limited by their own address",
            settings.listen_addr
        );
    }
    // Everything that can fail runs before the monitor socket is published:
    // users DB, TCP bind, router, then bind_monitor (which also cleans up a
    // stale unix socket). The guard unlinks a unix socket on shutdown.
    let config = match UserStore::open(&settings.users_db) {
        Ok(users) => web_safe_block::Config::new(&settings, users),
        Err(e) => return fail(e),
    };
    rt.block_on(async move {
        let limits = config.limits;
        let listener = match tokio::net::TcpListener::bind(listen).await {
            Ok(l) => l,
            Err(e) => return fail(format!("failed to bind {listen}: {e}")),
        };
        let events = Arc::new(EventQueue::new(queue_len));
        let router = match web_safe_block::build_router(config, events.clone()) {
            Ok(r) => r,
            Err(e) => return fail(e),
        };
        let (monitor_listener, monitor_guard) = match monitor::bind_monitor(&monitor_addr) {
            Ok(b) => b,
            Err(e) => return fail(format!("failed to bind monitor {monitor_addr}: {e}")),
        };
        let bound_monitor = monitor_listener.local_addr();
        monitor::spawn_monitor(monitor_listener, events);
        // Report the addresses actually bound: port 0 resolves to a real port
        // and a unix monitor reports its published path.
        let bound = listener.local_addr().map(|a| a.to_string());
        println!(
            "web-safe-block: monitor on {bound_monitor} (queue {queue_len} events)"
        );
        println!(
            "web-safe-block: listening on {}, upstream {}, users {}, session TTL {}s, cookie_secure={}",
            bound.as_deref().unwrap_or("?"),
            settings.upstream,
            settings.users_db.display(),
            settings.session_ttl_secs,
            settings.cookie_secure
        );
        let rc = match web_safe_block::serve(listener, router, limits, shutdown_signal()).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(format!("server error: {e}")),
        };
        drop(monitor_guard);
        rc
    })
}

/// Resolve on Ctrl-C or (unix) SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Option<(PathBuf, String, Option<String>)> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parse_args_cases() {
        let ok = |p: &str, c: &str, n: Option<&str>| {
            Some((PathBuf::from(p), c.to_string(), n.map(str::to_string)))
        };
        assert_eq!(parse(&["serve"]), ok("config.toml", "serve", None));
        assert_eq!(
            parse(&["-c", "x.toml", "serve"]),
            ok("x.toml", "serve", None)
        );
        assert_eq!(
            parse(&["add-user", "-c", "/a/b.toml"]),
            ok("/a/b.toml", "add-user", None)
        );
        assert_eq!(
            parse(&["remove-user", "bob"]),
            ok("config.toml", "remove-user", Some("bob"))
        );
        assert_eq!(
            parse(&["remove-user", "-c", "/a/b.toml", "bob"]),
            ok("/a/b.toml", "remove-user", Some("bob"))
        );
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["-c"]), None);
        assert_eq!(parse(&["serve", "-c"]), None);
        assert_eq!(parse(&["-c", "x.toml"]), None);
        assert_eq!(parse(&["-c", "a", "-c", "b", "serve"]), None);
        assert_eq!(parse(&["a", "b", "c"]), None);
    }
}
