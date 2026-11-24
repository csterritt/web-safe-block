/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The `/__wsb/` session endpoints: login, logout page, and logout.

use std::net::SocketAddr;
use std::time::SystemTime;

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::with_outcome;
use crate::monitor::EventKind;
use crate::rate_limit::{refund_attempt, reserve_attempt};
use crate::sessions::{Session, evictions, hash_token, new_token, unix_micros, valid_session};
use crate::state::AppState;
use crate::users::StoredSession;
use crate::util::{
    LOGOUT_PATH, clear_cookie_header, cross_site, html_response, login_page, message_para,
    page_shell, plain_response, rate_limit_key, sanitize_next, session_cookie_header,
    session_tokens,
};

pub(crate) fn forbidden() -> Response {
    with_outcome(
        plain_response(StatusCode::FORBIDDEN, "Forbidden"),
        EventKind::Forbidden,
        None,
    )
}

/// A bookmark or refresh of the login URL bounces to the front page,
/// which answers with the login form until the visitor is authenticated.
pub(crate) async fn login_redirect() -> Response {
    let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, HeaderValue::from_static("/"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    with_outcome(resp, EventKind::LoginPage, None)
}

#[derive(Deserialize)]
pub(crate) struct LoginForm {
    #[serde(default)]
    user: String,
    phrase: String,
    #[serde(default)]
    next: String,
}

pub(crate) async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let next = sanitize_next(&form.next);
    if cross_site(&headers, state.config.cookie_secure) {
        return forbidden();
    }
    let key = rate_limit_key(&headers, Some(peer));
    if !reserve_attempt(
        &mut state.failures.lock().unwrap(),
        state.config.limits.max_failure_keys,
        &key,
    ) {
        return with_outcome(
            html_response(
                StatusCode::TOO_MANY_REQUESTS,
                login_page(
                    &state.config.front_page_message,
                    Some("Too many attempts, try again later."),
                    &next,
                ),
            ),
            EventKind::RateLimited,
            None,
        );
    }
    // Bound how many logins queue for the Argon2 slot; extras get a 503.
    let waiter = match state.login_waiters.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            return with_outcome(
                html_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    login_page(
                        &state.config.front_page_message,
                        Some("Server busy, try again shortly."),
                        &next,
                    ),
                ),
                EventKind::LoginBusy,
                None,
            );
        }
    };
    // Serialize Argon2 hashing (one ~12 MiB run at a time) but run it on the
    // blocking pool so Tokio workers stay free. The owned guards move into
    // the closure: dropping this future must not release them early.
    let looked_up = {
        let hash = state.hash_slot.clone().lock_owned().await;
        let users = state.config.users.clone();
        let (user_name, phrase) = (form.user.clone(), form.phrase.clone());
        tokio::task::spawn_blocking(move || {
            let _held = (hash, waiter);
            users.lookup(&user_name, &phrase)
        })
        .await
    };
    match looked_up {
        Err(e) => {
            eprintln!("web-safe-block: user lookup failed: {e}");
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            login_error(&state.config.front_page_message, &next)
        }
        Ok(Err(e)) => {
            eprintln!("web-safe-block: user lookup failed: {e}");
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            login_error(&state.config.front_page_message, &next)
        }
        Ok(Ok(None)) => {
            tokio::time::sleep(state.config.fail_delay).await;
            with_outcome(
                html_response(
                    StatusCode::UNAUTHORIZED,
                    login_page(
                        &state.config.front_page_message,
                        Some("Incorrect user name or phrase."),
                        &next,
                    ),
                ),
                EventKind::LoginFailed,
                None,
            )
        }
        Ok(Ok(Some(user))) => {
            let token = new_token();
            let expires = SystemTime::now() + state.config.session_ttl;
            // Serialize the session write: memory and the database must never
            // disagree about which sessions exist, and `created` stamps must
            // be unique and increasing. The owned guard moves into the
            // closure so a cancelled request cannot release it mid-write.
            let writes = state.session_writes.clone().lock_owned().await;
            let st = state.clone();
            let user_name = user.name.clone();
            let cookie_string = hash_token(&token);
            let saved = tokio::task::spawn_blocking(move || {
                let mut last_created = writes;
                let created = unix_micros().max(*last_created + 1);
                *last_created = created;
                let stored = StoredSession {
                    cookie_string: cookie_string.clone(),
                    user_name: user_name.clone(),
                    expires,
                    created,
                };
                // Plan the evictions first; the map is mutated only once the
                // rows are durably written, so a failed save evicts nothing.
                let removed =
                    evictions(&st.sessions.lock().unwrap(), &st.config.limits, &user_name);
                st.config.users.save_session(&stored, &removed).map(|()| {
                    let mut sessions = st.sessions.lock().unwrap();
                    for k in &removed {
                        sessions.remove(k);
                    }
                    sessions.insert(
                        cookie_string,
                        Session {
                            expires,
                            user: user_name,
                            created,
                        },
                    );
                })
            })
            .await;
            if !matches!(saved, Ok(Ok(()))) {
                match &saved {
                    Ok(Err(e)) => eprintln!("web-safe-block: session save failed: {e}"),
                    Err(e) => eprintln!("web-safe-block: session save failed: {e}"),
                    _ => {}
                }
                refund_attempt(&mut state.failures.lock().unwrap(), &key);
                return login_error(&state.config.front_page_message, &next);
            }
            println!("web-safe-block: user '{}' logged in", user.name);
            // A success undoes only its own reserved attempt; earlier
            // failures against other names keep counting.
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
            let h = resp.headers_mut();
            h.insert(
                header::LOCATION,
                HeaderValue::from_str(&next).unwrap_or(HeaderValue::from_static("/")),
            );
            h.insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&session_cookie_header(
                    &token,
                    state.config.session_ttl,
                    state.config.cookie_secure,
                ))
                .unwrap(),
            );
            with_outcome(resp, EventKind::LoginSucceeded, Some(user.name))
        }
    }
}

/// The 500 page for a database error mid-login.
fn login_error(front: &str, next: &str) -> Response {
    with_outcome(
        html_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            login_page(front, Some("Server error, try again later."), next),
        ),
        EventKind::LoginError,
        None,
    )
}

fn logout_form_html(message: Option<&str>) -> String {
    let msg = message_para(message);
    page_shell(
        "Log out",
        &format!(
            "{msg}<form method=\"post\" action=\"{LOGOUT_PATH}\">\n<button type=\"submit\">Log out</button>\n</form>\n"
        ),
    )
}

/// Log-out form; GETting it changes nothing.
pub(crate) async fn logout_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = valid_session(&state, &headers);
    with_outcome(
        html_response(StatusCode::OK, logout_form_html(None)),
        EventKind::LogoutPage,
        user,
    )
}

/// Acknowledge log-out only once the session is durably revoked in users.db.
/// On failure the cookie and the in-memory session are kept.
pub(crate) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if cross_site(&headers, state.config.cookie_secure) {
        return forbidden();
    }
    // Every wsb_session cookie offered is revoked — a path-scoped sibling
    // cookie may shadow the real one.
    let hashes: Vec<String> = session_tokens(&headers)
        .into_iter()
        .map(|t| hash_token(&t))
        .collect();
    let done = |user: Option<String>| {
        let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
        let h = resp.headers_mut();
        h.insert(header::LOCATION, HeaderValue::from_static("/"));
        h.insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&clear_cookie_header(state.config.cookie_secure)).unwrap(),
        );
        with_outcome(resp, EventKind::Logout, user)
    };
    // The owned guard moves into the closure so a cancelled request cannot
    // release it while the delete is still running.
    let writes = state.session_writes.clone().lock_owned().await;
    let st = state.clone();
    let gone = tokio::task::spawn_blocking(move || {
        let _writes = writes;
        // Only hashes the map actually holds can be live sessions; unknown
        // values need no database write at all.
        let (present, user) = {
            let sessions = st.sessions.lock().unwrap();
            let present: Vec<String> = hashes
                .iter()
                .filter(|h| sessions.contains_key(*h))
                .cloned()
                .collect();
            let user = present
                .first()
                .and_then(|h| sessions.get(h))
                .map(|s| s.user.clone());
            (present, user)
        };
        if present.is_empty() {
            return (false, user, Ok(()));
        }
        let result = st.config.users.delete_sessions(&present);
        if result.is_ok() {
            let mut sessions = st.sessions.lock().unwrap();
            for h in &present {
                sessions.remove(h);
            }
        }
        (true, user, result)
    })
    .await;
    match gone {
        Ok((false, _, _)) => done(None),
        Ok((true, user, Ok(()))) => done(user),
        result => {
            match &result {
                Ok((_, _, Err(e))) => eprintln!("web-safe-block: session delete failed: {e}"),
                Err(e) => eprintln!("web-safe-block: session delete failed: {e}"),
                _ => {}
            }
            let user = result.ok().and_then(|(_, u, _)| u);
            with_outcome(
                html_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    logout_form_html(Some("Log out failed, try again.")),
                ),
                EventKind::LogoutError,
                user,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::monitor::EventQueue;
    use crate::state::{Config, Limits};
    use crate::users::{self, UserStore};

    fn state_with_alice() -> AppState {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wsb-auth-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(users::DB_FILE);
        let conn = users::open_for_add(&path).unwrap();
        users::add_users(
            &conn,
            "alice Correct-Horse-Battery-42\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(conn);
        let config = Config {
            users: Arc::new(UserStore::open(&path).unwrap()),
            upstream: "http://127.0.0.1:1".parse().unwrap(),
            front_page_message: "Site Description Here".into(),
            session_ttl: Duration::from_secs(600),
            cookie_secure: false,
            fail_delay: Duration::ZERO,
            limits: Limits::default(),
        };
        AppState::new(config, Arc::new(EventQueue::new(10)))
    }

    #[test]
    fn root_page_is_prebuilt() {
        let state = state_with_alice();
        let expected = login_page("Site Description Here", None, "/");
        assert_eq!(&state.root_page[..], expected.as_bytes());
    }

    #[test]
    fn logout_form_uses_shared_shell() {
        let page = logout_form_html(Some("<b>oops</b>"));
        assert!(
            page.starts_with("<!DOCTYPE html>\n<html>\n<head>"),
            "{page}"
        );
        assert!(page.contains("<title>Log out</title>"), "{page}");
        assert!(
            page.contains("<p>&lt;b&gt;oops&lt;/b&gt;</p>\n<form"),
            "{page}"
        );
        assert!(page.contains("action=\"/__wsb/logout\""), "{page}");
        assert!(page.ends_with("</body>\n</html>\n"), "{page}");
    }

    /// Cancelling a login mid-hash must not release the hash slot early:
    /// the owned guard lives in the blocking closure.
    ///
    /// Current-thread runtime: when `try_lock` first fails, the login future
    /// is suspended at `spawn_blocking(..).await` — the guard is already
    /// inside the detached blocking closure, so aborting cannot drop it.
    #[tokio::test]
    async fn hash_slot_survives_request_cancellation() {
        let state = state_with_alice();
        let peer: SocketAddr = "127.0.0.1:4321".parse().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        for _ in 0..10 {
            let st = state.clone();
            let task = tokio::spawn(login(
                State(st),
                ConnectInfo(peer),
                HeaderMap::from_iter([(
                    header::HeaderName::from_static("sec-fetch-site"),
                    HeaderValue::from_static("same-origin"),
                )]),
                Form(LoginForm {
                    user: "alice".into(),
                    phrase: "Correct-Horse-Battery-42".into(),
                    next: String::new(),
                }),
            ));
            // Poll tightly until the Argon2 hash is actually in progress.
            while state.hash_slot.try_lock().is_ok() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "login never held the hash slot"
                );
                tokio::task::yield_now().await;
            }
            task.abort();
            let Err(e) = task.await else {
                continue; // login finished before the abort landed; retry
            };
            assert!(e.is_cancelled());
            if state.hash_slot.try_lock().is_ok() {
                // Either the slot was released early (the bug this tests
                // for) or the hash finished in the abort window; retry.
                continue;
            }
            // Held after the abort: the guard outlives the cancelled
            // future. It must be released once the blocking hash exits.
            for _ in 0..1000 {
                if state.hash_slot.try_lock().is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("hash slot never released");
        }
        panic!("hash slot was released early on every attempt");
    }
}
