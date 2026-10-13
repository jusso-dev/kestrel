//! Process counts and the busiest processes.
//!
//! Counts come from grouping `sysinfo` processes by name. The top 10 by CPU
//! and the top 10 by memory are separate series. A configured name that is
//! not running is reported as `0` so a count alert can fire. CPU usage follows
//! sysinfo: `1.0` is 100 percent of one CPU, and the first sample can be `0`.

use crate::metrics::{PROCESS_COUNT, PROCESS_CPU_RATIO, PROCESS_MEMORY_BYTES};
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::collections::BTreeMap;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

/// How many processes to publish for each top-N list.
pub const TOP_PROCESSES: usize = 10;

pub struct ProcessCollector {
    system: System,
    interval: Duration,
    top_n: usize,
    names: Option<Vec<String>>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            interval: DEFAULT_INTERVAL,
            top_n: TOP_PROCESSES,
            names: None,
        }
    }

    /// Emit `kestrel_process_count` for each name, including names with no
    /// matching process. Top-N series still cover the whole host.
    pub fn with_names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let mut collector = Self::new();
        collector.names = Some(normalise_names(names));
        collector
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &str {
        "proc"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_memory().with_cpu(),
        );
        let mut rows = Vec::with_capacity(self.system.processes().len());
        for process in self.system.processes().values() {
            let name = process.name().to_string_lossy();
            let name = if name.is_empty() {
                "(unknown)".to_string()
            } else {
                name.into_owned()
            };
            rows.push(ProcessRow {
                name,
                pid: process.pid().to_string(),
                cpu_ratio: finite(f64::from(process.cpu_usage()) / 100.0),
                memory_bytes: finite(process.memory() as f64),
            });
        }
        Ok(rows_to_samples(
            rows,
            self.names.as_deref(),
            self.top_n,
            now_ms,
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcessRow {
    pub name: String,
    pub pid: String,
    pub cpu_ratio: f64,
    pub memory_bytes: f64,
}

/// Build count and top-N samples. Equal CPU or memory keeps the lower pid
/// string so the published set does not flicker.
pub(crate) fn rows_to_samples(
    mut rows: Vec<ProcessRow>,
    configured: Option<&[String]>,
    top_n: usize,
    now_ms: i64,
) -> Vec<Sample> {
    let mut samples = Vec::new();
    match configured {
        Some(names) => {
            for name in names {
                let count = rows.iter().filter(|row| row.name == *name).count();
                samples.push(sample(
                    PROCESS_COUNT,
                    &[("name", name.as_str())],
                    count as f64,
                    now_ms,
                ));
            }
        }
        None => {
            let mut counts = BTreeMap::<&str, u64>::new();
            for row in &rows {
                *counts.entry(row.name.as_str()).or_default() += 1;
            }
            for (name, count) in counts {
                samples.push(sample(
                    PROCESS_COUNT,
                    &[("name", name)],
                    count as f64,
                    now_ms,
                ));
            }
        }
    }

    rows.sort_by(|left, right| {
        right
            .cpu_ratio
            .total_cmp(&left.cpu_ratio)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    for row in rows.iter().take(top_n) {
        samples.push(sample(
            PROCESS_CPU_RATIO,
            &[("name", row.name.as_str()), ("pid", row.pid.as_str())],
            row.cpu_ratio,
            now_ms,
        ));
    }

    rows.sort_by(|left, right| {
        right
            .memory_bytes
            .total_cmp(&left.memory_bytes)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    for row in rows.iter().take(top_n) {
        samples.push(sample(
            PROCESS_MEMORY_BYTES,
            &[("name", row.name.as_str()), ("pid", row.pid.as_str())],
            row.memory_bytes,
            now_ms,
        ));
    }
    samples
}

fn normalise_names(names: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        let name = name.into();
        if name.is_empty() || out.iter().any(|existing| existing == &name) {
            continue;
        }
        out.push(name);
    }
    out
}

fn finite(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, pid: &str, cpu: f64, memory: f64) -> ProcessRow {
        ProcessRow {
            name: name.to_string(),
            pid: pid.to_string(),
            cpu_ratio: cpu,
            memory_bytes: memory,
        }
    }

    fn labelled<'a>(sample: &'a Sample, key: &str) -> Option<&'a str> {
        sample
            .labels
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    fn find<'a>(samples: &'a [Sample], metric: &str, name: &str, pid: Option<&str>) -> &'a Sample {
        samples
            .iter()
            .find(|sample| {
                sample.name == metric
                    && labelled(sample, "name") == Some(name)
                    && match pid {
                        Some(pid) => labelled(sample, "pid") == Some(pid),
                        None => true,
                    }
            })
            .unwrap_or_else(|| panic!("missing {metric} name={name} pid={pid:?}"))
    }

    #[test]
    fn groups_counts_and_keeps_the_top_of_each_list() {
        let rows = vec![
            row("nginx", "2", 0.10, 500.0),
            row("nginx", "4", 0.80, 100.0),
            row("sshd", "3", 0.40, 900.0),
            row("idle", "1", 0.01, 10.0),
        ];
        let now_ms = 1_700_000_000_000;
        let samples = rows_to_samples(rows, None, 2, now_ms);

        assert_eq!(find(&samples, PROCESS_COUNT, "nginx", None).value, 2.0);
        assert_eq!(find(&samples, PROCESS_COUNT, "sshd", None).value, 1.0);
        assert_eq!(find(&samples, PROCESS_COUNT, "idle", None).value, 1.0);
        assert!(samples.iter().all(|sample| sample.timestamp_ms == now_ms));

        let cpu: Vec<_> = samples
            .iter()
            .filter(|sample| sample.name == PROCESS_CPU_RATIO)
            .map(|sample| labelled(sample, "pid").unwrap())
            .collect();
        assert_eq!(cpu, ["4", "3"]);

        let memory: Vec<_> = samples
            .iter()
            .filter(|sample| sample.name == PROCESS_MEMORY_BYTES)
            .map(|sample| labelled(sample, "pid").unwrap())
            .collect();
        assert_eq!(memory, ["3", "2"]);
        assert_eq!(
            find(&samples, PROCESS_CPU_RATIO, "nginx", Some("4")).value,
            0.80
        );
        assert_eq!(
            find(&samples, PROCESS_MEMORY_BYTES, "sshd", Some("3")).value,
            900.0
        );
    }

    #[test]
    fn configured_names_report_zero_when_absent() {
        let rows = vec![row("nginx", "9", 0.2, 50.0)];
        let samples = rows_to_samples(
            rows,
            Some(&["nginx".to_string(), "missing".to_string()]),
            10,
            7,
        );
        assert_eq!(find(&samples, PROCESS_COUNT, "nginx", None).value, 1.0);
        assert_eq!(find(&samples, PROCESS_COUNT, "missing", None).value, 0.0);
        assert_eq!(
            samples
                .iter()
                .filter(|sample| sample.name == PROCESS_COUNT)
                .count(),
            2
        );
    }

    #[test]
    fn equal_usage_breaks_ties_by_pid() {
        let rows = vec![row("a", "20", 0.5, 5.0), row("b", "3", 0.5, 5.0)];
        let samples = rows_to_samples(rows, None, 1, 1);
        let cpu = samples
            .iter()
            .find(|sample| sample.name == PROCESS_CPU_RATIO)
            .unwrap();
        assert_eq!(labelled(cpu, "pid"), Some("20"));
    }

    #[test]
    fn this_host_reports_the_current_process() {
        let mut collector = ProcessCollector::new();
        let now_ms = 1_700_000_000_000;
        let samples = collector.collect(now_ms).expect("process collect");
        assert!(samples.iter().all(|sample| sample.timestamp_ms == now_ms));
        assert!(samples
            .iter()
            .any(|sample| sample.name == PROCESS_COUNT && sample.value >= 1.0));
        assert!(
            samples
                .iter()
                .filter(|sample| sample.name == PROCESS_CPU_RATIO)
                .count()
                <= TOP_PROCESSES
        );
        assert!(
            samples
                .iter()
                .filter(|sample| sample.name == PROCESS_MEMORY_BYTES)
                .count()
                <= TOP_PROCESSES
        );
        assert!(samples.iter().all(|sample| sample.value.is_finite()));

        let mut system = System::new();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::new(),
        );
        let name = system
            .process(pid)
            .expect("test process")
            .name()
            .to_string_lossy()
            .into_owned();
        assert!(
            samples.iter().any(|sample| {
                sample.name == PROCESS_COUNT
                    && labelled(sample, "name") == Some(name.as_str())
                    && sample.value >= 1.0
            }),
            "missing count for {name}"
        );
    }
}
