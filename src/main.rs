use std::net::SocketAddr;

use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;

#[tokio::main]
async fn main() {
    let config = match web_safe_block::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("web-safe-block: configuration error: {e}");
            std::process::exit(1);
        }
    };
    let listen: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("web-safe-block: LISTEN_ADDR is not a valid socket address");
            std::process::exit(1);
        });
    println!(
        "web-safe-block: listening on {listen}, upstream {}, session TTL {}s, cookie_secure={}",
        config.upstream,
        config.session_ttl.as_secs(),
        config.cookie_secure
    );
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("web-safe-block: failed to bind {listen}: {e}");
            std::process::exit(1);
        });
    let service: IntoMakeServiceWithConnectInfo<_, SocketAddr> =
        web_safe_block::build_router(config).into_make_service_with_connect_info();
    if let Err(e) = axum::serve(listener, service).await {
        eprintln!("web-safe-block: server error: {e}");
        std::process::exit(1);
    }
}
