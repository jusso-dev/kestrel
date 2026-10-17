//! Collectors used by the Kestrel agent.
//!
//! Each collector implements [`Collector`] and stamps samples with the
//! `now_ms` it is given, so callers and tests supply the clock.

mod command;
mod cpu;
mod diskio;
mod filesystem;
mod http;
mod logs;
mod memory;
mod metrics;
mod network;
mod perfdata;
mod process;
mod prom_scrape;
mod selfstats;
mod service;
mod uptime;

pub use command::{resolve_executable, run_command, CommandCheck, CommandError, CommandOutput};
pub use cpu::CpuCollector;
pub use diskio::DiskIoCollector;
pub use filesystem::FilesystemCollector;
pub use http::{
    expiry_from_der, probe_tls_expiry, run_http_check, with_expiry, HttpCheck, HttpOutcome,
    RecordingVerifier,
};
pub use logs::{
    load_log_offsets, save_log_offsets, LogError, LogOffset, LogTailer, MAX_LOG_LINES_PER_TICK,
    MAX_LOG_LINE_BYTES,
};
pub use memory::MemoryCollector;
pub use metrics::{BUFFER_DROPPED_TOTAL, DOCUMENTED};
pub use network::NetworkCollector;
pub use perfdata::{parse_perfdata, PerfPoint};
pub use process::{ProcessCollector, TOP_PROCESSES};
pub use prom_scrape::{
    encode_exposition, parse_exposition, relabel, scrape_prometheus, to_agent_samples,
    validate_exposition, ExpositionSample,
};
pub use selfstats::SelfStatsCollector;
pub use service::ServiceCollector;
pub use uptime::UptimeCollector;

use kestrel_proto::Sample;
use std::time::Duration;

/// Default scrape interval for the built-in host collectors.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// A collector produces samples on each tick.
pub trait Collector: Send {
    fn name(&self) -> &str;
    fn interval(&self) -> Duration;
    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError>;
}

/// A collector could not read its source.
#[derive(Debug)]
pub struct CollectError {
    message: String,
}

impl CollectError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

pub(crate) fn sample(name: &str, labels: &[(&str, &str)], value: f64, now_ms: i64) -> Sample {
    Sample {
        name: name.to_string(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
        value,
        timestamp_ms: now_ms,
    }
}

/// The host collectors shipped with the agent, in a stable order.
pub fn builtin_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(CpuCollector::new()),
        Box::new(MemoryCollector::new()),
        Box::new(FilesystemCollector::new()),
        Box::new(DiskIoCollector::new()),
        Box::new(NetworkCollector::new()),
        Box::new(UptimeCollector::new()),
        Box::new(SelfStatsCollector::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label<'a>(sample: &'a Sample, key: &str) -> Option<&'a str> {
        sample
            .labels
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn collectors_use_the_supplied_clock_and_labels() {
        let now_ms = 1_700_000_000_000;
        let mut collectors = builtin_collectors();
        let mut saw_cpu = false;
        let mut saw_memory = false;
        let mut saw_filesystem = false;
        let mut saw_network = false;
        for collector in &mut collectors {
            let samples = collector
                .collect(now_ms)
                .unwrap_or_else(|err| panic!("{}: {err}", collector.name()));
            assert!(
                samples.iter().all(|sample| sample.timestamp_ms == now_ms),
                "{} did not use the supplied clock",
                collector.name()
            );
            for sample in &samples {
                assert!(
                    DOCUMENTED.contains(&sample.name.as_str()),
                    "undocumented metric {}",
                    sample.name
                );
                assert!(sample.value.is_finite(), "{}", sample.name);
            }
            saw_cpu |= samples.iter().any(|sample| {
                sample.name == metrics::CPU_USAGE_RATIO && label(sample, "cpu") == Some("total")
            });
            saw_memory |= samples
                .iter()
                .any(|sample| sample.name == metrics::MEMORY_USED_BYTES);
            saw_filesystem |= samples.iter().any(|sample| {
                sample.name == metrics::FILESYSTEM_FREE_BYTES && label(sample, "mount").is_some()
            });
            saw_network |= samples.iter().any(|sample| {
                sample.name == metrics::NETWORK_RECEIVE_BYTES_TOTAL
                    && label(sample, "iface").is_some()
            });
            for sample in &samples {
                if sample.name.starts_with("kestrel_disk_") {
                    assert!(
                        label(sample, "device").is_some_and(|value| !value.is_empty()),
                        "{}",
                        sample.name
                    );
                }
            }
        }
        assert!(saw_cpu, "missing kestrel_cpu_usage_ratio{{cpu=total}}");
        assert!(saw_memory, "missing kestrel_memory_used_bytes");
        assert!(
            saw_filesystem,
            "missing kestrel_filesystem_free_bytes{{mount}}"
        );
        assert!(
            saw_network,
            "missing kestrel_network_receive_bytes_total{{iface}}"
        );
    }
}
