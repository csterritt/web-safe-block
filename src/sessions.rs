/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Login sessions: token minting, lookup, bounded insertion, and the
//! write-through to the `sessions` table in users.db.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::state::{AppState, Limits};
use crate::util::{session_tokens, to_hex};

pub(crate) struct Session {
    pub expires: SystemTime,
    pub user: String,
    /// Creation stamp (unix microseconds, unique and increasing); evictions
    /// take the smallest stamp, not the earliest expiry.
    pub created: i64,
}

/// Now in unix microseconds (used for `created` stamps).
pub(crate) fn unix_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

/// Hex SHA-256 of a raw token; the map key and the stored cookie_string.
pub(crate) fn hash_token(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

/// The user name of a valid, unexpired session, if the request has one.
/// Every `wsb_session` cookie is checked: the first that resolves wins
/// (a path-scoped cookie may shadow the real one). Expired ones seen on
/// the way are dropped lazily.
pub(crate) fn valid_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    // Only 64 lowercase-hex bytes can be a minted token (see `new_token`);
    // every other attacker-controlled value is knowably invalid and is
    // neither hashed nor looked up. Hashing also happens outside the map
    // lock so malformed cookies can't hold it.
    let keys: Vec<String> = session_tokens(headers)
        .into_iter()
        .filter(|t| t.len() == 64 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .map(|t| hash_token(&t))
        .collect();
    if keys.is_empty() {
        return None;
    }
    let mut sessions = state.sessions.lock().unwrap();
    let now = SystemTime::now();
    for key in keys {
        match sessions.get(&key) {
            Some(s) if s.expires > now => return Some(s.user.clone()),
            Some(_) => {
                sessions.remove(&key);
            }
            None => {}
        }
    }
    None
}

/// The keys `insert_session` would remove for a new session by `user`,
/// without touching the map: expired entries (only when a cap is hit),
/// then the user's earliest-created until under the per-user cap, then the
/// globally earliest-created until under the total cap.
pub(crate) fn evictions(
    sessions: &HashMap<String, Session>,
    limits: &Limits,
    user: &str,
) -> Vec<String> {
    let now = SystemTime::now();
    let mut removed: Vec<String> = Vec::new();
    let mut gone: HashSet<&str> = HashSet::new();
    let mut len = sessions.len();
    let mut user_count = sessions.values().filter(|s| s.user == user).count();
    if len >= limits.max_sessions || user_count >= limits.max_sessions_per_user {
        for (k, s) in sessions {
            if s.expires <= now {
                if s.user == user {
                    user_count -= 1;
                }
                removed.push(k.clone());
                gone.insert(k);
            }
        }
        len -= removed.len();
    }
    while user_count >= limits.max_sessions_per_user {
        let Some(oldest) = sessions
            .iter()
            .filter(|(k, s)| s.user == user && !gone.contains(k.as_str()))
            .min_by(|(k1, s1), (k2, s2)| (s1.created, *k1).cmp(&(s2.created, *k2)))
            .map(|(k, _)| k.as_str())
        else {
            break;
        };
        gone.insert(oldest);
        removed.push(oldest.to_string());
        user_count -= 1;
        len -= 1;
    }
    while len >= limits.max_sessions {
        let Some(oldest) = sessions
            .iter()
            .filter(|(k, _)| !gone.contains(k.as_str()))
            .min_by(|(k1, s1), (k2, s2)| (s1.created, *k1).cmp(&(s2.created, *k2)))
            .map(|(k, _)| k.as_str())
        else {
            break;
        };
        gone.insert(oldest);
        removed.push(oldest.to_string());
        len -= 1;
    }
    removed
}

/// Insert a session under `key`, evicting to stay within the per-user and
/// global caps. Returns the key of every entry it removed.
#[cfg(test)]
pub(crate) fn insert_session(
    sessions: &mut HashMap<String, Session>,
    limits: &Limits,
    key: String,
    session: Session,
) -> Vec<String> {
    let removed = evictions(sessions, limits, &session.user);
    for k in &removed {
        sessions.remove(k);
    }
    sessions.insert(key, session);
    removed
}

/// Drop expired rows in the database, then rebuild the in-memory map from
/// whatever rows remain. Picks up removals made by other processes (such as
/// `remove-user`) as well as expiries. Returns the largest `created` stamp
/// loaded, so the caller can keep issuing increasing stamps. Callers hold
/// `session_writes`; the map lock is only taken for the final swap.
pub(crate) fn reload_sessions(state: &AppState) -> rusqlite::Result<i64> {
    let now = SystemTime::now();
    // A failed delete (locked/read-only db) must not prevent the reload.
    if let Err(e) = state.config.users.delete_expired_sessions(now) {
        eprintln!("web-safe-block: expired-session delete failed: {e}");
    }
    let stored = state.config.users.load_sessions(now)?;
    let mut max_created = 0i64;
    let mut sessions = state.sessions.lock().unwrap();
    sessions.clear();
    for s in stored {
        max_created = max_created.max(s.created);
        sessions.insert(
            s.cookie_string,
            Session {
                expires: s.expires,
                user: s.user_name,
                created: s.created,
            },
        );
    }
    Ok(max_created)
}

pub(crate) fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
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

    fn session(user: &str, secs: u64, created: i64) -> Session {
        Session {
            expires: SystemTime::now() + Duration::from_secs(secs),
            user: user.to_string(),
            created,
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
        // Per-user cap: the earliest-created of the user's sessions is evicted.
        let mut removed = Vec::new();
        for i in 0..3 {
            removed.extend(insert_session(
                &mut sessions,
                &l,
                format!("a{i}"),
                session("alice", 100 + i, i as i64),
            ));
        }
        assert_eq!(removed, ["a0"]);
        let mut keys: Vec<&String> = sessions.keys().collect();
        keys.sort();
        assert_eq!(keys, ["a1", "a2"]);

        // Global cap: the globally earliest-created session goes, even when
        // it has the latest expiry (e.g. the TTL was raised after restart).
        assert!(insert_session(&mut sessions, &l, "b0".into(), session("bob", 50, 10)).is_empty());
        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains_key("a1") || sessions.contains_key("a2"));
        assert!(sessions.contains_key("b0"));
        let removed = insert_session(&mut sessions, &l, "b1".into(), session("bob", 40, 11));
        assert_eq!(sessions.len(), 3);
        assert!(!sessions.contains_key("a1"), "earliest created evicted");
        assert_eq!(removed, ["a1"]);

        // An expired session does not count against a cap.
        let mut sessions = HashMap::new();
        sessions.insert("old".into(), session("alice", 0, 1));
        let mut removed = Vec::new();
        removed.extend(insert_session(
            &mut sessions,
            &l,
            "n1".into(),
            session("alice", 10, 2),
        ));
        removed.extend(insert_session(
            &mut sessions,
            &l,
            "n2".into(),
            session("alice", 11, 3),
        ));
        assert!(!sessions.contains_key("old"));
        assert!(sessions.contains_key("n1") && sessions.contains_key("n2"));
        assert_eq!(removed, ["old"]);
    }

    fn state_with_alice() -> AppState {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::monitor::EventQueue;
        use crate::state::Config;
        use crate::users::{self, UserStore};

        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wsb-sessions-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::users::DB_FILE);
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

    /// Values that cannot be a minted token — wrong length or non-hex —
    /// resolve to None without reaching the map (and without panicking).
    #[test]
    fn valid_session_filters_token_format() {
        use axum::http::{HeaderValue, header};

        let state = state_with_alice();
        let token = new_token();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(hash_token(&token), session("alice", 600, 1));
        let cookie = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("wsb_session={v}")).unwrap(),
            );
            h
        };
        assert_eq!(
            valid_session(&state, &cookie(&token)),
            Some("alice".to_string())
        );
        assert_eq!(valid_session(&state, &cookie(&token.to_uppercase())), None);
        assert_eq!(valid_session(&state, &cookie(&format!("{token}0"))), None);
        assert_eq!(valid_session(&state, &cookie(&"a".repeat(4096))), None);
        assert_eq!(valid_session(&state, &cookie("short")), None);
    }
}
