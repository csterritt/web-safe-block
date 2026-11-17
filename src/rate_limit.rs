//! Bounded per-client login failure tracking for the login endpoint.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const RATE_LIMIT_MAX_FAILURES: usize = 10;
pub(crate) const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Under one lock: prune the key's stale timestamps, refuse once it has
/// RATE_LIMIT_MAX_FAILURES in the window, else record this attempt now.
pub(crate) fn reserve_attempt(
    failures: &mut HashMap<String, Vec<Instant>>,
    max_keys: usize,
    key: &str,
) -> bool {
    let now = Instant::now();
    if let Some(v) = failures.get_mut(key) {
        v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
        if v.is_empty() {
            failures.remove(key);
        }
    }
    if failures
        .get(key)
        .is_some_and(|v| v.len() >= RATE_LIMIT_MAX_FAILURES)
    {
        return false;
    }
    if !failures.contains_key(key) && failures.len() >= max_keys {
        failures.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
            !v.is_empty()
        });
        if failures.len() >= max_keys
            && let Some(oldest) = failures
                .iter()
                .max_by_key(|(_, v)| v.last().map(|t| now.duration_since(*t)).unwrap_or_default())
                .map(|(k, _)| k.clone())
        {
            failures.remove(&oldest);
        }
    }
    let v = failures.entry(key.to_string()).or_default();
    if v.len() >= RATE_LIMIT_MAX_FAILURES {
        v.drain(..v.len() + 1 - RATE_LIMIT_MAX_FAILURES);
    }
    v.push(now);
    true
}

/// Undo a reserved attempt that turned out not to be a login failure.
pub(crate) fn refund_attempt(failures: &mut HashMap<String, Vec<Instant>>, key: &str) {
    if let Some(v) = failures.get_mut(key) {
        v.pop();
        if v.is_empty() {
            failures.remove(key);
        }
    }
}

pub(crate) fn clear_failures(failures: &Mutex<HashMap<String, Vec<Instant>>>, key: &str) {
    failures.lock().unwrap().remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_caps() {
        let max_keys = 3;
        let mut failures = HashMap::new();
        for i in 0..RATE_LIMIT_MAX_FAILURES {
            assert!(reserve_attempt(&mut failures, max_keys, "a"));
            let _ = i;
        }
        assert!(!reserve_attempt(&mut failures, max_keys, "a"));
        assert_eq!(failures["a"].len(), RATE_LIMIT_MAX_FAILURES);

        // New keys evict the key whose most recent failure is oldest.
        let mut failures = HashMap::new();
        assert!(reserve_attempt(&mut failures, max_keys, "old"));
        std::thread::sleep(Duration::from_millis(2));
        for k in ["b", "c"] {
            assert!(reserve_attempt(&mut failures, max_keys, k));
        }
        assert_eq!(failures.len(), 3);
        assert!(reserve_attempt(&mut failures, max_keys, "new"));
        assert_eq!(failures.len(), 3);
        assert!(!failures.contains_key("old"), "{failures:?}");

        // Refund removes the newest timestamp and the key when empty.
        refund_attempt(&mut failures, "new");
        assert!(!failures.contains_key("new"));
    }
}
