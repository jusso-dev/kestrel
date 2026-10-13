//! CPU utilisation. Values are ratios in the range 0.0 to 1.0 for one CPU,
//! except `cpu="total"`, which is the mean across CPUs.

use crate::metrics::CPU_USAGE_RATIO;
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::time::Duration;
use sysinfo::{CpuRefreshKind, System};

pub struct CpuCollector {
    system: System,
    interval: Duration,
}

impl CpuCollector {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_list(CpuRefreshKind::new().with_cpu_usage());
        Self {
            system,
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl Default for CpuCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &str {
        "cpu"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        if self.system.cpus().is_empty() {
            self.system
                .refresh_cpu_list(CpuRefreshKind::new().with_cpu_usage());
        }
        self.system.refresh_cpu_usage();
        let mut samples = Vec::with_capacity(self.system.cpus().len() + 1);
        samples.push(sample(
            CPU_USAGE_RATIO,
            &[("cpu", "total")],
            f64::from(self.system.global_cpu_usage()) / 100.0,
            now_ms,
        ));
        for (index, cpu) in self.system.cpus().iter().enumerate() {
            let label = index.to_string();
            samples.push(sample(
                CPU_USAGE_RATIO,
                &[("cpu", &label)],
                f64::from(cpu.cpu_usage()) / 100.0,
                now_ms,
            ));
        }
        Ok(samples)
    }
}
