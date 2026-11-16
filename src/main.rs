use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use web_safe_block::users::{self, DB_FILE, UserStore};

const USAGE: &str = "usage: web-safe-block <command>

commands:
  add-user   read 'user-name pass phrase words...' lines from stdin into ./users.db
  serve      run the proxy (users from ./users.db)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("add-user") if args.len() == 1 => add_user(),
        Some("serve") if args.len() == 1 => serve(),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("web-safe-block: {msg}");
    ExitCode::FAILURE
}

fn add_user() -> ExitCode {
    let conn = match users::open_for_add(Path::new(DB_FILE)) {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot open {DB_FILE}: {e}")),
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

fn serve() -> ExitCode {
    let config =
        match UserStore::open(Path::new(DB_FILE)).and_then(web_safe_block::Config::from_env) {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
    let listen: SocketAddr = match std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
    {
        Ok(a) => a,
        Err(_) => return fail("LISTEN_ADDR is not a valid socket address"),
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return fail(format!("cannot start runtime: {e}")),
    };
    rt.block_on(async move {
        println!(
            "web-safe-block: listening on {listen}, upstream {}, session TTL {}s, cookie_secure={}",
            config.upstream,
            config.session_ttl.as_secs(),
            config.cookie_secure
        );
        let listener = match tokio::net::TcpListener::bind(listen).await {
            Ok(l) => l,
            Err(e) => return fail(format!("failed to bind {listen}: {e}")),
        };
        let service: IntoMakeServiceWithConnectInfo<_, SocketAddr> =
            web_safe_block::build_router(config).into_make_service_with_connect_info();
        match axum::serve(listener, service).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(format!("server error: {e}")),
        }
    })
}
