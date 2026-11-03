//! Failed sign-in throttling per account and per source address.
//!
//! Each key gets a fixed window that starts at its first failure. Once a key
//! reaches its limit, sign-in for that key is refused with 429 until the window
//! ends; refused attempts do not extend it. Keys are counted whether or not the
//! account exists, so a refusal does not reveal which email addresses are
//! registered. The account key includes the source address, so nobody can lock
//! another user out from elsewhere; the source limit bounds guessing across
//! accounts.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Keys tracked per map before expired windows are pruned.
const MAX_TRACKED: usize = 100_000;

/// Sign-in is refused until `retry_after` has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttled {
    pub retry_after: Duration,
}

/// Identifies the window in which an attempt was counted.
#[derive(Debug, Clone, Copy)]
pub struct Reservation(Instant);

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    failures: u32,
}

struct Counter<K> {
    limit: u32,
    windows: Mutex<HashMap<K, Window>>,
}

impl<K: Eq + Hash + Clone> Counter<K> {
    fn new(limit: u32) -> Self {
        Self {
            limit: limit.max(1),
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, Window>> {
        self.windows
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn check(
        &self,
        windows: &HashMap<K, Window>,
        key: &K,
        window: Duration,
        now: Instant,
    ) -> Result<(), Throttled> {
        match windows.get(key) {
            Some(entry) if entry.failures >= self.limit && entry.started + window > now => {
                Err(Throttled {
                    retry_after: entry.started + window - now,
                })
            }
            _ => Ok(()),
        }
    }

    fn add(&self, windows: &mut HashMap<K, Window>, key: K, window: Duration, now: Instant) {
        if windows.len() >= MAX_TRACKED && !windows.contains_key(&key) {
            windows.retain(|_, entry| entry.started + window > now);
            if windows.len() >= MAX_TRACKED {
                // Still full of live windows: drop the oldest one that is not
                // throttled, so flooding new keys cannot release a lockout.
                // Only when every window is throttled does the oldest go.
                let limit = self.limit;
                let oldest = |throttled: bool| {
                    windows
                        .iter()
                        .filter(|(_, entry)| throttled || entry.failures < limit)
                        .min_by_key(|(_, entry)| entry.started)
                        .map(|(key, _)| key.clone())
                };
                if let Some(key) = oldest(false).or_else(|| oldest(true)) {
                    windows.remove(&key);
                }
            }
        }
        let entry = windows.entry(key).or_insert(Window {
            started: now,
            failures: 0,
        });
        if entry.started + window <= now {
            *entry = Window {
                started: now,
                failures: 0,
            };
        }
        entry.failures = entry.failures.saturating_add(1);
    }
}

/// Failed sign-in counters keyed by account and source, and by source alone.
///
/// [`LoginGuard::begin`] counts an attempt as a failure before the password is
/// checked, so parallel guesses cannot overrun the limit;
/// [`LoginGuard::release`] takes it back.
pub struct LoginGuard {
    window: Duration,
    accounts: Counter<String>,
    sources: Counter<IpAddr>,
    /// Bounds concurrent Argon2 verifications on the blocking pool.
    pub(crate) verify_permits: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Argon2 verifications that may run at once.
const VERIFY_PERMITS: usize = 4;
/// Longest failure window. Also keeps `Instant + window` from overflowing.
const MAX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

impl LoginGuard {
    pub fn new(max_per_account: u32, max_per_source: u32, window: Duration) -> Self {
        Self {
            window: window.clamp(Duration::from_secs(1), MAX_WINDOW),
            accounts: Counter::new(max_per_account),
            sources: Counter::new(max_per_source),
            verify_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        }
    }

    /// Refuse when the account or the source has used its failures, otherwise
    /// count this attempt against both.
    pub fn begin(&self, account: &str, source: Option<IpAddr>) -> Result<Reservation, Throttled> {
        self.begin_at(account, source, Instant::now())
    }

    /// Take back one attempt that was not a wrong password: it succeeded, or
    /// the server failed before it could judge it. Failures and other in-flight
    /// attempts stay, and a newer window is never touched by a slow request.
    pub fn release(&self, account: &str, source: Option<IpAddr>, reservation: Reservation) {
        if let Some(entry) = self.accounts.lock().get_mut(&account_key(account, source)) {
            if entry.started <= reservation.0 {
                entry.failures = entry.failures.saturating_sub(1);
            }
        }
        if let Some(ip) = source {
            if let Some(entry) = self.sources.lock().get_mut(&source_key(ip)) {
                if entry.started <= reservation.0 {
                    entry.failures = entry.failures.saturating_sub(1);
                }
            }
        }
    }

    fn begin_at(
        &self,
        account: &str,
        source: Option<IpAddr>,
        now: Instant,
    ) -> Result<Reservation, Throttled> {
        let account = account_key(account, source);
        let source = source.map(source_key);
        // Lock order is always accounts then sources.
        let mut accounts = self.accounts.lock();
        let mut sources = self.sources.lock();
        let by_account = self.accounts.check(&accounts, &account, self.window, now);
        let by_source = source
            .map(|ip| self.sources.check(&sources, &ip, self.window, now))
            .unwrap_or(Ok(()));
        match (by_account, by_source) {
            (Err(a), Err(b)) => {
                return Err(Throttled {
                    retry_after: a.retry_after.max(b.retry_after),
                })
            }
            (Err(err), _) | (_, Err(err)) => return Err(err),
            _ => {}
        }
        self.accounts.add(&mut accounts, account, self.window, now);
        if let Some(ip) = source {
            self.sources.add(&mut sources, ip, self.window, now);
        }
        Ok(Reservation(now))
    }
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self::new(10, 50, Duration::from_secs(15 * 60))
    }
}

fn account_key(email: &str, source: Option<IpAddr>) -> String {
    let source = source
        .map(|ip| source_key(ip).to_string())
        .unwrap_or_default();
    format!("{}|{source}", email.trim().to_lowercase())
}

/// IPv6 clients usually control a whole /64, so count the prefix.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::V6(segments.into())
            }
        },
    }
}

/// The client address for `peer`. `X-Forwarded-For` is only read when the
/// direct peer is a trusted proxy, and then the right-most untrusted hop wins.
pub fn client_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted: &[IpAddr],
) -> Option<IpAddr> {
    let peer = peer?;
    let is_trusted = |address: IpAddr| {
        let canonical = canonical_ip(address);
        trusted.iter().any(|ip| canonical_ip(*ip) == canonical)
    };
    if !is_trusted(peer) {
        return Some(peer);
    }
    let Some(header) = forwarded_for else {
        return Some(peer);
    };
    let mut client = peer;
    for hop in header.rsplit(',') {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            break;
        };
        client = ip;
        if !is_trusted(ip) {
            break;
        }
    }
    Some(client)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    #[test]
    fn account_is_throttled_after_its_limit_and_released_after_the_window() {
        let guard = LoginGuard::new(3, 100, WINDOW);
        let start = Instant::now();
        for _ in 0..3 {
            assert!(guard.begin_at("a@example.com", None, start).is_ok());
        }
        let refused = guard.begin_at("A@Example.com ", None, start).unwrap_err();
        assert_eq!(refused.retry_after, WINDOW);
        assert!(guard.begin_at("b@example.com", None, start).is_ok());
        assert!(guard
            .begin_at("a@example.com", None, start + WINDOW)
            .is_ok());
    }

    #[test]
    fn another_source_cannot_lock_an_account_out() {
        let guard = LoginGuard::new(2, 100, WINDOW);
        let now = Instant::now();
        let attacker: IpAddr = "198.51.100.1".parse().unwrap();
        let owner: IpAddr = "203.0.113.1".parse().unwrap();
        guard
            .begin_at("a@example.com", Some(attacker), now)
            .unwrap();
        guard
            .begin_at("a@example.com", Some(attacker), now)
            .unwrap();
        assert!(guard
            .begin_at("A@example.com", Some(attacker), now)
            .is_err());
        assert!(guard.begin_at("a@example.com", Some(owner), now).is_ok());
    }

    #[test]
    fn flooding_new_keys_does_not_release_a_throttled_account() {
        let guard = LoginGuard::new(2, u32::MAX, WINDOW);
        let now = Instant::now();
        guard.begin_at("victim@example.com", None, now).unwrap();
        guard.begin_at("victim@example.com", None, now).unwrap();
        let later = now + Duration::from_secs(1);
        for n in 0..MAX_TRACKED + 10 {
            guard
                .begin_at(&format!("flood{n}@example.com"), None, later)
                .unwrap();
        }
        assert!(guard.begin_at("victim@example.com", None, later).is_err());
    }

    #[test]
    fn a_huge_window_is_clamped_instead_of_overflowing() {
        let guard = LoginGuard::new(1, 100, Duration::MAX);
        let now = Instant::now();
        guard.begin_at("a@example.com", None, now).unwrap();
        let refused = guard.begin_at("a@example.com", None, now).unwrap_err();
        assert_eq!(refused.retry_after, MAX_WINDOW);
    }

    #[test]
    fn refused_attempts_do_not_extend_the_window() {
        let guard = LoginGuard::new(1, 100, WINDOW);
        let start = Instant::now();
        guard.begin_at("a@example.com", None, start).unwrap();
        for _ in 0..10 {
            assert!(guard.begin_at("a@example.com", None, start).is_err());
        }
        assert!(guard
            .begin_at("a@example.com", None, start + WINDOW)
            .is_ok());
    }

    #[test]
    fn source_is_throttled_across_accounts_and_success_keeps_earlier_failures() {
        let guard = LoginGuard::new(100, 2, WINDOW);
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let now = Instant::now();
        guard.begin_at("one@example.com", Some(ip), now).unwrap();
        let reservation = guard.begin_at("two@example.com", Some(ip), now).unwrap();
        guard.release("two@example.com", Some(ip), reservation);
        guard.begin_at("three@example.com", Some(ip), now).unwrap();
        assert!(guard.begin_at("four@example.com", Some(ip), now).is_err());
        assert!(guard.begin_at("four@example.com", None, now).is_ok());
    }

    #[test]
    fn successful_sign_ins_never_throttle_a_shared_source() {
        let guard = LoginGuard::new(100, 2, WINDOW);
        let ip: IpAddr = "192.0.2.8".parse().unwrap();
        let now = Instant::now();
        for n in 0..10 {
            let account = format!("user{n}@example.com");
            let reservation = guard.begin_at(&account, Some(ip), now).unwrap();
            guard.release(&account, Some(ip), reservation);
        }
    }

    #[test]
    fn success_releases_only_its_own_attempt() {
        let guard = LoginGuard::new(3, 100, WINDOW);
        let now = Instant::now();
        guard.begin_at("a@example.com", None, now).unwrap();
        let success = guard.begin_at("a@example.com", None, now).unwrap();
        guard.begin_at("a@example.com", None, now).unwrap();
        guard.release("a@example.com", None, success);
        assert!(guard.begin_at("a@example.com", None, now).is_ok());
        assert!(guard.begin_at("a@example.com", None, now).is_err());
    }

    #[test]
    fn late_success_does_not_release_a_new_window() {
        let guard = LoginGuard::new(1, 1, WINDOW);
        let now = Instant::now();
        let ip = "192.0.2.9".parse().unwrap();
        let old = guard.begin_at("a@example.com", Some(ip), now).unwrap();
        guard
            .begin_at("a@example.com", Some(ip), now + WINDOW)
            .unwrap();
        guard.release("a@example.com", Some(ip), old);
        assert!(guard
            .begin_at("a@example.com", Some(ip), now + WINDOW)
            .is_err());
    }

    #[test]
    fn ipv6_sources_share_a_slash_64() {
        let guard = LoginGuard::new(100, 1, WINDOW);
        let now = Instant::now();
        guard
            .begin_at("a@example.com", Some("2001:db8::1".parse().unwrap()), now)
            .unwrap();
        assert!(guard
            .begin_at(
                "b@example.com",
                Some("2001:db8::ffff:1".parse().unwrap()),
                now
            )
            .is_err());
        assert!(guard
            .begin_at(
                "b@example.com",
                Some("2001:db8:0:1::1".parse().unwrap()),
                now
            )
            .is_ok());
    }

    #[test]
    fn forwarded_for_is_only_trusted_from_a_trusted_proxy() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let peer: IpAddr = "198.51.100.9".parse().unwrap();
        assert_eq!(
            client_ip(Some(peer), Some("203.0.113.5"), &[proxy]),
            Some(peer)
        );
        assert_eq!(
            client_ip(Some(proxy), Some("203.0.113.5, 10.0.0.1"), &[proxy]),
            Some("203.0.113.5".parse().unwrap())
        );
        assert_eq!(
            client_ip(Some(proxy), Some("1.1.1.1, 203.0.113.5"), &[proxy]),
            Some("203.0.113.5".parse().unwrap())
        );
        assert_eq!(client_ip(Some(proxy), None, &[proxy]), Some(proxy));
        assert_eq!(
            client_ip(Some(proxy), Some("garbage"), &[proxy]),
            Some(proxy)
        );
        assert_eq!(client_ip(None, Some("203.0.113.5"), &[proxy]), None);
        assert_eq!(
            client_ip(
                Some("::ffff:10.0.0.1".parse().unwrap()),
                Some("203.0.113.5"),
                &[proxy],
            ),
            Some("203.0.113.5".parse().unwrap())
        );
        assert_eq!(
            client_ip(Some(proxy), Some("203.0.113.5, ::ffff:10.0.0.1"), &[proxy],),
            Some("203.0.113.5".parse().unwrap())
        );
    }
}
