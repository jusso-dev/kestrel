//! Memory, swap, and (on Unix) load averages.

#[cfg(unix)]
use crate::metrics::{LOAD1, LOAD15, LOAD5};
use crate::metrics::{
    MEMORY_AVAILABLE_BYTES, MEMORY_TOTAL_BYTES, MEMORY_USED_BYTES, SWAP_TOTAL_BYTES,
    SWAP_USED_BYTES,
};
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::time::Duration;
use sysinfo::System;

pub struct MemoryCollector {
    system: System,
    interval: Duration,
}

impl MemoryCollector {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl Default for MemoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &str {
        "memory"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        self.system.refresh_memory();
        let samples = vec![
            sample(
                MEMORY_USED_BYTES,
                &[],
                self.system.used_memory() as f64,
                now_ms,
            ),
            sample(
                MEMORY_AVAILABLE_BYTES,
                &[],
                self.system.available_memory() as f64,
                now_ms,
            ),
            sample(
                MEMORY_TOTAL_BYTES,
                &[],
                self.system.total_memory() as f64,
                now_ms,
            ),
            sample(SWAP_USED_BYTES, &[], self.system.used_swap() as f64, now_ms),
            sample(
                SWAP_TOTAL_BYTES,
                &[],
                self.system.total_swap() as f64,
                now_ms,
            ),
        ];
        // Load averages are a Unix concept. Windows has no equivalent in sysinfo.
        #[cfg(unix)]
        {
            let mut samples = samples;
            let load = System::load_average();
            samples.push(sample(LOAD1, &[], load.one, now_ms));
            samples.push(sample(LOAD5, &[], load.five, now_ms));
            samples.push(sample(LOAD15, &[], load.fifteen, now_ms));
            return Ok(samples);
        }
        #[cfg(not(unix))]
        Ok(samples)
    }
}
