//! Runs every built-in collector on the machine executing the tests.

use kestrel_checks::{builtin_collectors, DOCUMENTED};
use std::time::Instant;

#[test]
fn every_collector_runs_on_this_host() {
    let mut collectors = builtin_collectors();
    let now_ms = 1_700_000_000_000;
    // The first tick warms sysinfo deltas. The timed tick is the one that
    // has to stay under 50 ms.
    for collector in &mut collectors {
        collector
            .collect(now_ms)
            .unwrap_or_else(|err| panic!("{}: {err}", collector.name()));
    }

    let mut names = Vec::new();
    for collector in &mut collectors {
        let started = Instant::now();
        let samples = collector
            .collect(now_ms + 30_000)
            .unwrap_or_else(|err| panic!("{}: {err}", collector.name()));
        let elapsed = started.elapsed();
        assert!(
            elapsed.as_millis() < 50,
            "{} took {} ms",
            collector.name(),
            elapsed.as_millis()
        );
        for sample in samples {
            assert_eq!(sample.timestamp_ms, now_ms + 30_000);
            assert!(
                DOCUMENTED.contains(&sample.name.as_str()),
                "undocumented metric {}",
                sample.name
            );
            names.push(sample.name);
        }
    }

    for required in [
        "kestrel_cpu_usage_ratio",
        "kestrel_memory_used_bytes",
        "kestrel_memory_available_bytes",
        "kestrel_memory_total_bytes",
        "kestrel_swap_used_bytes",
        "kestrel_swap_total_bytes",
        "kestrel_filesystem_free_bytes",
        "kestrel_filesystem_size_bytes",
        "kestrel_network_receive_bytes_total",
        "kestrel_network_transmit_bytes_total",
        "kestrel_uptime_seconds",
        "kestrel_agent_memory_bytes",
        "kestrel_agent_cpu_usage_ratio",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "missing {required} on this host"
        );
    }

    #[cfg(unix)]
    {
        for required in ["kestrel_load1", "kestrel_load5", "kestrel_load15"] {
            assert!(
                names.iter().any(|name| name == required),
                "missing {required}"
            );
        }
    }
    #[cfg(windows)]
    {
        assert!(
            names.iter().all(|name| !name.starts_with("kestrel_load")),
            "Windows must not emit load averages"
        );
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        assert!(
            names
                .iter()
                .any(|name| name == "kestrel_disk_read_bytes_total"),
            "this host should emit disk read counters"
        );
    }
}
