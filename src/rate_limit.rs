/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Bounded per-client login failure tracking for the login endpoint.

use std::collections::HashMap;
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
            && let Some(victim) = failures
                .iter()
                .min_by(|(_, v1), (_, v2)| (v1.len(), v1.last()).cmp(&(v2.len(), v2.last())))
                .map(|(k, _)| k.clone())
        {
            failures.remove(&victim);
        }
    }
    let v = failures.entry(key.to_string()).or_default();
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

    #[test]
    fn eviction_prefers_fewest_timestamps() {
        let max_keys = 3;
        let mut failures = HashMap::new();
        // A throttled key keeps its budget: it is never the eviction victim.
        for _ in 0..RATE_LIMIT_MAX_FAILURES {
            assert!(reserve_attempt(&mut failures, max_keys, "throttled"));
        }
        assert!(!reserve_attempt(&mut failures, max_keys, "throttled"));
        assert!(reserve_attempt(&mut failures, max_keys, "one-a"));
        std::thread::sleep(Duration::from_millis(2));
        assert!(reserve_attempt(&mut failures, max_keys, "one-b"));
        assert!(reserve_attempt(&mut failures, max_keys, "new"));
        assert!(failures.contains_key("throttled"), "{failures:?}");
        assert!(
            !failures.contains_key("one-a"),
            "oldest 1-failure key evicted"
        );
        assert!(failures.contains_key("one-b"));
    }
}
