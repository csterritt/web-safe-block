//! The `/__wsb/` session endpoints: login, logout page, and logout.

use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::with_outcome;
use crate::monitor::EventKind;
use crate::rate_limit::{clear_failures, refund_attempt, reserve_attempt};
use crate::sessions::{Session, insert_session, new_token, valid_session};
use crate::state::AppState;
use crate::util::{
    LOGOUT_PATH, SESSION_COOKIE, clear_cookie_header, client_key, cross_site, html_response,
    login_page, parse_cookies, sanitize_next, session_cookie_header,
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
    match state.config.users.lookup(&form.phrase) {
        Err(e) => {
            eprintln!("web-safe-block: user lookup failed: {e}");
            refund_attempt(&mut state.failures.lock().unwrap(), &key);
            with_outcome(
                html_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    login_page(Some("Server error, try again later."), &next),
                ),
                EventKind::LoginError,
                None,
            )
        }
        Ok(None) => {
            tokio::time::sleep(state.config.fail_delay).await;
            with_outcome(
                html_response(
                    StatusCode::UNAUTHORIZED,
                    login_page(Some("Incorrect phrase."), &next),
                ),
                EventKind::LoginFailed,
                None,
            )
        }
        Ok(Some(user)) => {
            println!("web-safe-block: user '{}' logged in", user.name);
            let token = new_token();
            insert_session(
                &mut state.sessions.lock().unwrap(),
                &state.config.limits,
                token.clone(),
                Session {
                    expires: Instant::now() + state.config.session_ttl,
                    user: user.name.clone(),
                },
            );
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

/// Log-out form; GETting it changes nothing.
pub(crate) async fn logout_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = valid_session(&state, &headers);
    let body = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Log out</title>\n</head>\n<body>\n<form method=\"post\" action=\"{LOGOUT_PATH}\">\n<button type=\"submit\">Log out</button>\n</form>\n</body>\n</html>\n"
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
        .and_then(|(_, token)| state.sessions.lock().unwrap().remove(&token))
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
