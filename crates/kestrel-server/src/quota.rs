//! Per-tenant sample quotas. Exceeding the bucket returns 429.

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use uuid::Uuid;

/// The tenant has used its sample allowance for this second.
#[derive(Debug)]
pub struct OverQuota;

type TenantLimiter = RateLimiter<Uuid, DefaultKeyedStateStore<Uuid>, DefaultClock>;

pub struct Quotas {
    limiter: TenantLimiter,
    configured: std::sync::Mutex<std::collections::HashMap<u32, TenantLimiter>>,
}

impl Quotas {
    pub fn per_second(rate: u32) -> Self {
        let rate = NonZeroU32::new(rate.max(1)).unwrap_or(NonZeroU32::MIN);
        Self {
            limiter: RateLimiter::keyed(Quota::per_second(rate)),
            configured: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn check(&self, tenant: Uuid, samples: u32) -> Result<(), OverQuota> {
        let samples = NonZeroU32::new(samples).ok_or(OverQuota)?;
        match self.limiter.check_key_n(&tenant, samples) {
            Ok(Ok(_)) => Ok(()),
            _ => Err(OverQuota),
        }
    }

    pub fn check_with_rate(&self, tenant: Uuid, samples: u32, rate: u32) -> Result<(), OverQuota> {
        let samples = NonZeroU32::new(samples).ok_or(OverQuota)?;
        let rate = NonZeroU32::new(rate).ok_or(OverQuota)?;
        let mut rates = self
            .configured
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let limiter = rates
            .entry(rate.get())
            .or_insert_with(|| RateLimiter::keyed(Quota::per_second(rate)));
        match limiter.check_key_n(&tenant, samples) {
            Ok(Ok(_)) => Ok(()),
            _ => Err(OverQuota),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_rejects_the_second_burst() {
        let quotas = Quotas::per_second(1);
        let tenant = Uuid::from_u128(1);
        assert!(quotas.check(tenant, 1).is_ok());
        assert!(quotas.check(tenant, 1).is_err());
        let other = Uuid::from_u128(2);
        assert!(quotas.check(other, 1).is_ok());
    }
}
