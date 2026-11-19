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
    Session, hash_token, insert_session, new_token, reload_sessions, valid_session,
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
    let users = state.config.users.clone();
    let (user_name, phrase) = (form.user.clone(), form.phrase.clone());
    let looked_up =
        tokio::task::spawn_blocking(move || users.lookup(&user_name, &phrase)).await;
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
            println!("web-safe-block: user '{}' logged in", user.name);
            let token = new_token();
            let expires = SystemTime::now() + state.config.session_ttl;
            let stored = StoredSession {
                cookie_string: hash_token(&token),
                user_name: user.name.clone(),
                expires,
            };
            {
                // Hold the lock across the write so memory and the database
                // never disagree about which sessions exist.
                let mut sessions = state.sessions.lock().unwrap();
                let removed = insert_session(
                    &mut sessions,
                    &state.config.limits,
                    stored.cookie_string.clone(),
                    Session {
                        expires,
                        user: user.name.clone(),
                    },
                );
                if let Err(e) = state.config.users.save_session(&stored, &removed) {
                    drop(sessions);
                    eprintln!("web-safe-block: session save failed: {e}");
                    if let Err(e) = reload_sessions(&state) {
                        eprintln!("web-safe-block: session reload failed: {e}");
                    }
                    refund_attempt(&mut state.failures.lock().unwrap(), &key);
                    return login_error(&next);
                }
            }
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

/// Log-out form; GETting it changes nothing.
pub(crate) async fn logout_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = valid_session(&state, &headers);
    let body = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Log out</title>\n{PAGE_STYLE}</head>\n<body>\n<form method=\"post\" action=\"{LOGOUT_PATH}\">\n<button type=\"submit\">Log out</button>\n</form>\n</body>\n</html>\n"
    );
    with_outcome(
        html_response(StatusCode::OK, body),
        EventKind::LogoutPage,
        user,
    )
}

pub(crate) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if cross_site(&headers) {
        return forbidden();
    }
    let user = parse_cookies(&headers)
        .into_iter()
        .find(|(n, _)| n == SESSION_COOKIE)
        .and_then(|(_, token)| {
            let hash = hash_token(&token);
            let removed = state.sessions.lock().unwrap().remove(&hash);
            if removed.is_some()
                && let Err(e) = state.config.users.delete_sessions(&[hash])
            {
                eprintln!("web-safe-block: session delete failed: {e}");
            }
            removed
        })
        .map(|s| s.user);
    let mut resp = (StatusCode::SEE_OTHER, ()).into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, HeaderValue::from_static("/"));
    h.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie_header(state.config.cookie_secure)).unwrap(),
    );
    with_outcome(resp, EventKind::Logout, user)
}
