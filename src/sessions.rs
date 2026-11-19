//! Login sessions: token minting, lookup, bounded insertion, and the
//! write-through to the `sessions` table in users.db.

use std::collections::HashMap;
use std::time::SystemTime;

use axum::http::HeaderMap;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::state::{AppState, Limits};
use crate::util::{SESSION_COOKIE, parse_cookies};

pub(crate) struct Session {
    pub expires: SystemTime,
    pub user: String,
}

/// Hex SHA-256 of a raw token; the map key and the stored cookie_string.
pub(crate) fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The user name of a valid, unexpired session, if the request has one.
pub(crate) fn valid_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = parse_cookies(headers)
        .into_iter()
        .find(|(n, _)| n == SESSION_COOKIE)?
        .1;
    let key = hash_token(&token);
    let mut sessions = state.sessions.lock().unwrap();
    match sessions.get(&key) {
        Some(s) if s.expires > SystemTime::now() => Some(s.user.clone()),
        Some(_) => {
            sessions.remove(&key);
            None
        }
        None => None,
    }
}

/// Insert a session under `key`, evicting to stay within the per-user and
/// global caps. Returns the key of every entry it removed.
pub(crate) fn insert_session(
    sessions: &mut HashMap<String, Session>,
    limits: &Limits,
    key: String,
    session: Session,
) -> Vec<String> {
    let now = SystemTime::now();
    let mut removed = Vec::new();
    let user_count = |sessions: &HashMap<String, Session>| {
        sessions.values().filter(|s| s.user == session.user).count()
    };
    if sessions.len() >= limits.max_sessions || user_count(sessions) >= limits.max_sessions_per_user
    {
        sessions.retain(|k, s| {
            let keep = s.expires > now;
            if !keep {
                removed.push(k.clone());
            }
            keep
        });
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
        removed.push(oldest);
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
        removed.push(oldest);
    }
    sessions.insert(key, session);
    removed
}

/// Drop expired rows in the database, then rebuild the in-memory map from
/// whatever rows remain. Picks up removals made by other processes (such as
/// `remove-user`) as well as expiries.
pub(crate) fn reload_sessions(state: &AppState) -> rusqlite::Result<()> {
    let now = SystemTime::now();
    let mut sessions = state.sessions.lock().unwrap();
    state.config.users.delete_expired_sessions(now)?;
    let stored = state.config.users.load_sessions(now)?;
    sessions.clear();
    for s in stored {
        sessions.insert(
            s.cookie_string,
            Session {
                expires: s.expires,
                user: s.user_name,
            },
        );
    }
    Ok(())
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
            expires: SystemTime::now() + Duration::from_secs(secs),
            user: user.to_string(),
        }
    }

    #[test]
    fn token_hash_is_sha256_hex() {
        // SHA-256("abc")
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hash_token(&new_token()).len(), 64);
    }

    #[test]
    fn session_caps() {
        let l = limits();
        let mut sessions = HashMap::new();
        // Per-user cap: the oldest of the user's sessions is evicted.
        let mut removed = Vec::new();
        for i in 0..3 {
            removed.extend(insert_session(
                &mut sessions,
                &l,
                format!("a{i}"),
                session("alice", 100 + i),
            ));
        }
        assert_eq!(removed, ["a0"]);
        let mut keys: Vec<&String> = sessions.keys().collect();
        keys.sort();
        assert_eq!(keys, ["a1", "a2"]);

        // Global cap: the globally earliest-expiring session goes.
        assert!(insert_session(&mut sessions, &l, "b0".into(), session("bob", 50)).is_empty());
        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains_key("a1") || sessions.contains_key("a2"));
        assert!(sessions.contains_key("b0"));
        let removed = insert_session(&mut sessions, &l, "b1".into(), session("bob", 40));
        assert_eq!(sessions.len(), 3);
        assert!(!sessions.contains_key("b0"), "earliest expiry evicted");
        assert_eq!(removed, ["b0"]);

        // An expired session does not count against a cap.
        let mut sessions = HashMap::new();
        sessions.insert("old".into(), session("alice", 0));
        let mut removed = Vec::new();
        removed.extend(insert_session(
            &mut sessions,
            &l,
            "n1".into(),
            session("alice", 10),
        ));
        removed.extend(insert_session(
            &mut sessions,
            &l,
            "n2".into(),
            session("alice", 11),
        ));
        assert!(!sessions.contains_key("old"));
        assert!(sessions.contains_key("n1") && sessions.contains_key("n2"));
        assert_eq!(removed, ["old"]);
    }
}
