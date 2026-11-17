//! Login sessions: token minting, lookup, and bounded insertion.

use std::collections::HashMap;
use std::time::Instant;

use axum::http::HeaderMap;
use rand::Rng;

use crate::state::{AppState, Limits};
use crate::util::{SESSION_COOKIE, parse_cookies};

pub(crate) struct Session {
    pub expires: Instant,
    pub user: String,
}

/// The user name of a valid, unexpired session, if the request has one.
pub(crate) fn valid_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = parse_cookies(headers)
        .into_iter()
        .find(|(n, _)| n == SESSION_COOKIE)?
        .1;
    let mut sessions = state.sessions.lock().unwrap();
    match sessions.get(&token) {
        Some(s) if s.expires > Instant::now() => Some(s.user.clone()),
        Some(_) => {
            sessions.remove(&token);
            None
        }
        None => None,
    }
}

/// Insert a session, evicting to stay within the per-user and global caps.
pub(crate) fn insert_session(
    sessions: &mut HashMap<String, Session>,
    limits: &Limits,
    token: String,
    session: Session,
) {
    let now = Instant::now();
    let user_count = |sessions: &HashMap<String, Session>| {
        sessions.values().filter(|s| s.user == session.user).count()
    };
    if sessions.len() >= limits.max_sessions || user_count(sessions) >= limits.max_sessions_per_user
    {
        sessions.retain(|_, s| s.expires > now);
    }
    while user_count(sessions) >= limits.max_sessions_per_user {
        let Some(oldest) = sessions
            .iter()
            .filter(|(_, s)| s.user == session.user)
            .min_by_key(|(_, s)| s.expires)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        sessions.remove(&oldest);
    }
    while sessions.len() >= limits.max_sessions {
        let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, s)| s.expires)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        sessions.remove(&oldest);
    }
    sessions.insert(token, session);
}

pub(crate) fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limits() -> Limits {
        Limits {
            max_sessions: 3,
            max_sessions_per_user: 2,
            ..Limits::default()
        }
    }

    fn session(user: &str, secs: u64) -> Session {
        Session {
            expires: Instant::now() + Duration::from_secs(secs),
            user: user.to_string(),
        }
    }

    #[test]
    fn session_caps() {
        let l = limits();
        let mut sessions = HashMap::new();
        // Per-user cap: the oldest of the user's sessions is evicted.
        for i in 0..3 {
            insert_session(
                &mut sessions,
                &l,
                format!("a{i}"),
                session("alice", 100 + i),
            );
        }
        let mut keys: Vec<&String> = sessions.keys().collect();
        keys.sort();
        assert_eq!(keys, ["a1", "a2"]);

        // Global cap: the globally earliest-expiring session goes.
        insert_session(&mut sessions, &l, "b0".into(), session("bob", 50));
        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains_key("a1") || sessions.contains_key("a2"));
        assert!(sessions.contains_key("b0"));
        insert_session(&mut sessions, &l, "b1".into(), session("bob", 40));
        assert_eq!(sessions.len(), 3);
        assert!(!sessions.contains_key("b0"), "earliest expiry evicted");

        // An expired session does not count against a cap.
        let mut sessions = HashMap::new();
        sessions.insert("old".into(), session("alice", 0));
        insert_session(&mut sessions, &l, "n1".into(), session("alice", 10));
        insert_session(&mut sessions, &l, "n2".into(), session("alice", 11));
        assert!(!sessions.contains_key("old"));
        assert!(sessions.contains_key("n1") && sessions.contains_key("n2"));
    }
}
