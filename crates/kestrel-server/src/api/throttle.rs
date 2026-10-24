//! Failed-login throttle and bounded password verification.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Failures allowed per email address and client address inside one window.
const MAX_FAILURES: u32 = 10;
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Upper bound on tracked addresses so random emails cannot grow memory.
const MAX_KEYS: usize = 10_000;
/// Argon2 verifications that may run at once on the blocking pool.
const VERIFY_PERMITS: usize = 4;

pub(crate) struct LoginThrottle {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
    verify: Semaphore,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            verify: Semaphore::new(VERIFY_PERMITS),
        }
    }
}

fn key(email: &str) -> String {
    email.trim().to_lowercase()
}

impl LoginThrottle {
    /// True when `email` has used up its failures for the current window.
    pub(crate) fn blocked(&self, email: &str) -> bool {
        let failures = self.failures.lock().unwrap_or_else(|err| err.into_inner());
        failures
            .get(&key(email))
            .is_some_and(|(count, since)| *count >= MAX_FAILURES && since.elapsed() < WINDOW)
    }

    pub(crate) fn failed(&self, email: &str) {
        let mut failures = self.failures.lock().unwrap_or_else(|err| err.into_inner());
        let key = key(email);
        if failures.len() >= MAX_KEYS && !failures.contains_key(&key) {
            failures.retain(|_, (_, since)| since.elapsed() < WINDOW);
            if failures.len() >= MAX_KEYS {
                if let Some(oldest) = failures
                    .iter()
                    .min_by_key(|(_, (_, since))| *since)
                    .map(|(key, _)| key.clone())
                {
                    failures.remove(&oldest);
                }
            }
        }
        let entry = failures.entry(key).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 = entry.0.saturating_add(1);
    }

    pub(crate) fn succeeded(&self, email: &str) {
        self.failures
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&key(email));
    }

    /// Verify off the async workers, with a bound on concurrent Argon2 runs.
    pub(crate) async fn verify(&self, password: &str, hash: &str) -> bool {
        let Ok(_permit) = self.verify.acquire().await else {
            return false;
        };
        let (password, hash) = (password.to_string(), hash.to_string());
        tokio::task::spawn_blocking(move || crate::passwords::verify_password(&password, &hash))
            .await
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.failures
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_throttle_blocks_after_repeated_failures_and_stays_bounded() {
        let throttle = LoginThrottle::default();
        for _ in 0..MAX_FAILURES {
            assert!(!throttle.blocked("Ops@Example.test"));
            throttle.failed("ops@example.test");
        }
        assert!(throttle.blocked(" OPS@example.test "));
        assert!(!throttle.blocked("other@example.test"));
        throttle.succeeded("ops@example.test");
        assert!(!throttle.blocked("ops@example.test"));
        for index in 0..MAX_KEYS + 50 {
            throttle.failed(&format!("user-{index}@example.test"));
        }
        assert!(throttle.tracked() <= MAX_KEYS);
    }

    #[tokio::test]
    async fn login_throttle_verifies_off_the_runtime() {
        let throttle = LoginThrottle::default();
        let hash = crate::passwords::hash_password("correct-horse").unwrap();
        assert!(throttle.verify("correct-horse", &hash).await);
        assert!(!throttle.verify("wrong", &hash).await);
    }
}
