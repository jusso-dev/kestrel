//! Failed sign-in throttling per account and per source address.
//!
//! Each key gets a fixed window that starts at its first failure. Once a key
//! reaches its limit, sign-in for that key is refused with 429 until the window
//! ends; refused attempts do not extend it. Keys are counted whether or not the account exists, so a refusal does
//! not reveal which email addresses are registered.

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
                // Still full of live windows: drop the oldest so new keys are
                // always counted rather than silently ignored.
                if let Some(oldest) = windows
                    .iter()
                    .min_by_key(|(_, entry)| entry.started)
                    .map(|(key, _)| key.clone())
                {
                    windows.remove(&oldest);
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

/// Failed sign-in counters keyed by account and by source address.
///
/// [`LoginGuard::begin`] counts an attempt as a failure before the password is
/// checked, so parallel guesses cannot overrun the limit;
/// [`LoginGuard::succeeded`] takes it back.
pub struct LoginGuard {
    window: Duration,
    accounts: Counter<String>,
    sources: Counter<IpAddr>,
}

impl LoginGuard {
    pub fn new(max_per_account: u32, max_per_source: u32, window: Duration) -> Self {
        Self {
            window: window.max(Duration::from_secs(1)),
            accounts: Counter::new(max_per_account),
            sources: Counter::new(max_per_source),
        }
    }

    /// Refuse when the account or the source has used its failures, otherwise
    /// count this attempt against both.
    pub fn begin(&self, account: &str, source: Option<IpAddr>) -> Result<(), Throttled> {
        self.begin_at(account, source, Instant::now())
    }

    /// The password was right: clear the account and return the source's
    /// attempt. The source keeps earlier failures so one valid account cannot
    /// reset guessing against others.
    pub fn succeeded(&self, account: &str, source: Option<IpAddr>) {
        self.accounts.lock().remove(&account_key(account));
        if let Some(ip) = source {
            if let Some(entry) = self.sources.lock().get_mut(&source_key(ip)) {
                entry.failures = entry.failures.saturating_sub(1);
            }
        }
    }

    fn begin_at(
        &self,
        account: &str,
        source: Option<IpAddr>,
        now: Instant,
    ) -> Result<(), Throttled> {
        let account = account_key(account);
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
        Ok(())
    }
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self::new(10, 50, Duration::from_secs(15 * 60))
    }
}

fn account_key(email: &str) -> String {
    email.trim().to_lowercase()
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
    if !trusted.contains(&peer) {
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
        if !trusted.contains(&ip) {
            break;
        }
    }
    Some(client)
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
        guard.begin_at("two@example.com", Some(ip), now).unwrap();
        guard.succeeded("two@example.com", Some(ip));
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
            guard.begin_at(&account, Some(ip), now).unwrap();
            guard.succeeded(&account, Some(ip));
        }
    }

    #[test]
    fn success_clears_the_account_counter() {
        let guard = LoginGuard::new(2, 100, WINDOW);
        let now = Instant::now();
        guard.begin_at("a@example.com", None, now).unwrap();
        guard.succeeded("a@example.com", None);
        guard.begin_at("a@example.com", None, now).unwrap();
        assert!(guard.begin_at("a@example.com", None, now).is_ok());
        assert!(guard.begin_at("a@example.com", None, now).is_err());
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
    }
}
