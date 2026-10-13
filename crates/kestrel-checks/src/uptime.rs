//! Host uptime in seconds.

use crate::metrics::UPTIME_SECONDS;
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::time::Duration;
use sysinfo::System;

pub struct UptimeCollector {
    interval: Duration,
}

impl UptimeCollector {
    pub fn new() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl Default for UptimeCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for UptimeCollector {
    fn name(&self) -> &str {
        "uptime"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        Ok(vec![sample(
            UPTIME_SECONDS,
            &[],
            System::uptime() as f64,
            now_ms,
        )])
    }
}
