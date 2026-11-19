//! The `/__wsb/` session endpoints: login, logout page, and logout.

use std::net::SocketAddr;
use std::time::SystemTime;

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::with_outcome;
use crate::monitor::EventKind;
use crate::rate_limit::{clear_failures, refund_attempt, reserve_attempt};
use crate::sessions::{
    Session, hash_token, insert_session, new_token, reload_sessions, unix_micros, valid_session,
};
use crate::state::AppState;
use crate::users::StoredSession;
use crate::util::{
    LOGOUT_PATH, PAGE_STYLE, SESSION_COOKIE, clear_cookie_header, client_key, cross_site,
    html_response, login_page, parse_cookies, sanitize_next, session_cookie_header,
};

pub(crate) fn forbidden() -> Response {
    with_outcome(
        (StatusCode::FORBIDDEN, "Forbidden").into_response(),
        EventKind::Forbidden,
        None,
    )
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
    if cross_site(&headers) {
        return forbidden();
    }
    let key = client_key(&headers, Some(peer));
    if !reserve_attempt(
        &mut state.failures.lock().unwrap(),
        state.config.limits.max_failure_keys,
        &key,
    ) {
        return with_outcome(
            html_response(
                StatusCode::TOO_MANY_REQUESTS,
                login_page(Some("Too many attempts, try again later."), &next),
            ),
            EventKind::RateLimited,
            None,
        );
    }
    // Serialize Argon2 hashing (one ~12 MiB run at a time) but run it on the
    // blocking pool so Tokio workers stay free.
    let looked_up = {
        let _hash = state.hash_slot.lock().await;
        let users = state.config.users.clone();
        let (user_name, phrase) = (form.user.clone(), form.phrase.clone());
        tokio::task::spawn_blocking(move || users.lookup(&user_name, &phrase)).await
    };
    match looked_up {
        Err(e) => {
            eprintln!("web-safe-block: user lookup failed: {e}");
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            login_error(&next)
        }
        Ok(Err(e)) => {
            eprintln!("web-safe-block: user lookup failed: {e}");
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            login_error(&next)
        }
        Ok(Ok(None)) => {
            tokio::time::sleep(state.config.fail_delay).await;
            with_outcome(
                html_response(
                    StatusCode::UNAUTHORIZED,
                    login_page(Some("Incorrect user name or phrase."), &next),
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
            // be unique and increasing.
            let mut last_created = state.session_writes.lock().await;
            let created = unix_micros().max(*last_created + 1);
            *last_created = created;
            let stored = StoredSession {
                cookie_string: hash_token(&token),
                user_name: user.name.clone(),
                expires,
                created,
            };
            let removed = {
                let mut sessions = state.sessions.lock().unwrap();
                insert_session(
                    &mut sessions,
                    &state.config.limits,
                    stored.cookie_string.clone(),
                    Session {
                        expires,
                        user: user.name.clone(),
                        created,
                    },
                )
            };
            let users = state.config.users.clone();
            let saved =
                tokio::task::spawn_blocking(move || users.save_session(&stored, &removed)).await;
            if !matches!(saved, Ok(Ok(()))) {
                match &saved {
                    Ok(Err(e)) => eprintln!("web-safe-block: session save failed: {e}"),
                    Err(e) => eprintln!("web-safe-block: session save failed: {e}"),
                    _ => {}
                }
                let st = state.clone();
                match tokio::task::spawn_blocking(move || reload_sessions(&st)).await {
                    Ok(Ok(max)) => *last_created = (*last_created).max(max),
                    Ok(Err(e)) => eprintln!("web-safe-block: session reload failed: {e}"),
                    Err(e) => eprintln!("web-safe-block: session reload failed: {e}"),
                }
                refund_attempt(&mut state.failures.lock().unwrap(), &key);
                return login_error(&next);
            }
            drop(last_created);
            println!("web-safe-block: user '{}' logged in", user.name);
            clear_failures(&state.failures, &key);
            let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
            let h = resp.headers_mut();
            h.insert(header::LOCATION, HeaderValue::from_str(&next).unwrap());
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
fn login_error(next: &str) -> Response {
    with_outcome(
        html_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            login_page(Some("Server error, try again later."), next),
        ),
        EventKind::LoginError,
        None,
    )
}

fn logout_form_html(message: Option<&str>) -> String {
    let msg = message
        .map(|m| format!("<p>{}</p>\n", crate::util::html_escape(m)))
        .unwrap_or_default();
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Log out</title>\n{PAGE_STYLE}</head>\n<body>\n{msg}<form method=\"post\" action=\"{LOGOUT_PATH}\">\n<button type=\"submit\">Log out</button>\n</form>\n</body>\n</html>\n"
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
    if cross_site(&headers) {
        return forbidden();
    }
    let token = parse_cookies(&headers)
        .into_iter()
        .find(|(n, _)| n == SESSION_COOKIE)
        .map(|(_, t)| t);
    let Some(token) = token else {
        let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
        let h = resp.headers_mut();
        h.insert(header::LOCATION, HeaderValue::from_static("/"));
        h.insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&clear_cookie_header(state.config.cookie_secure)).unwrap(),
        );
        return with_outcome(resp, EventKind::Logout, None);
    };
    let hash = hash_token(&token);
    let user = state
        .sessions
        .lock()
        .unwrap()
        .get(&hash)
        .map(|s| s.user.clone());
    let _writes = state.session_writes.lock().await;
    let users = state.config.users.clone();
    let gone = {
        let hash = hash.clone();
        tokio::task::spawn_blocking(move || users.delete_sessions(&[hash])).await
    };
    match gone {
        Ok(Ok(())) => {
            state.sessions.lock().unwrap().remove(&hash);
            let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
            let h = resp.headers_mut();
            h.insert(header::LOCATION, HeaderValue::from_static("/"));
            h.insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&clear_cookie_header(state.config.cookie_secure)).unwrap(),
            );
            with_outcome(resp, EventKind::Logout, user)
        }
        result => {
            match &result {
                Ok(Err(e)) => eprintln!("web-safe-block: session delete failed: {e}"),
                Err(e) => eprintln!("web-safe-block: session delete failed: {e}"),
                _ => {}
            }
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
