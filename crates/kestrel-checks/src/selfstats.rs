//! Resource use of the agent process itself.

use crate::metrics::{AGENT_CPU_USAGE_RATIO, AGENT_MEMORY_BYTES};
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::time::Duration;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

pub struct SelfStatsCollector {
    system: System,
    interval: Duration,
}

impl SelfStatsCollector {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl Default for SelfStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for SelfStatsCollector {
    fn name(&self) -> &str {
        "self"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        let pid = Pid::from_u32(std::process::id());
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::new().with_memory().with_cpu(),
        );
        let process = self
            .system
            .process(pid)
            .ok_or_else(|| CollectError::new("agent process was not found"))?;
        Ok(vec![
            sample(AGENT_MEMORY_BYTES, &[], process.memory() as f64, now_ms),
            sample(
                AGENT_CPU_USAGE_RATIO,
                &[],
                f64::from(process.cpu_usage()) / 100.0,
                now_ms,
            ),
        ])
    }
}
