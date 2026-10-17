//! Metric names emitted by the built-in collectors.
//!
//! `docs/metrics.md` must mention every name in [`DOCUMENTED`].

pub const CPU_USAGE_RATIO: &str = "kestrel_cpu_usage_ratio";
pub const MEMORY_USED_BYTES: &str = "kestrel_memory_used_bytes";
pub const MEMORY_AVAILABLE_BYTES: &str = "kestrel_memory_available_bytes";
pub const MEMORY_TOTAL_BYTES: &str = "kestrel_memory_total_bytes";
pub const SWAP_USED_BYTES: &str = "kestrel_swap_used_bytes";
pub const SWAP_TOTAL_BYTES: &str = "kestrel_swap_total_bytes";
pub const LOAD1: &str = "kestrel_load1";
pub const LOAD5: &str = "kestrel_load5";
pub const LOAD15: &str = "kestrel_load15";
pub const FILESYSTEM_FREE_BYTES: &str = "kestrel_filesystem_free_bytes";
pub const FILESYSTEM_SIZE_BYTES: &str = "kestrel_filesystem_size_bytes";
pub const FILESYSTEM_USED_RATIO: &str = "kestrel_filesystem_used_ratio";
pub const DISK_READ_BYTES_TOTAL: &str = "kestrel_disk_read_bytes_total";
pub const DISK_WRITTEN_BYTES_TOTAL: &str = "kestrel_disk_written_bytes_total";
pub const NETWORK_RECEIVE_BYTES_TOTAL: &str = "kestrel_network_receive_bytes_total";
pub const NETWORK_TRANSMIT_BYTES_TOTAL: &str = "kestrel_network_transmit_bytes_total";
pub const NETWORK_RECEIVE_PACKETS_TOTAL: &str = "kestrel_network_receive_packets_total";
pub const NETWORK_TRANSMIT_PACKETS_TOTAL: &str = "kestrel_network_transmit_packets_total";
pub const NETWORK_RECEIVE_ERRORS_TOTAL: &str = "kestrel_network_receive_errors_total";
pub const NETWORK_TRANSMIT_ERRORS_TOTAL: &str = "kestrel_network_transmit_errors_total";
pub const UPTIME_SECONDS: &str = "kestrel_uptime_seconds";
pub const AGENT_MEMORY_BYTES: &str = "kestrel_agent_memory_bytes";
pub const AGENT_CPU_USAGE_RATIO: &str = "kestrel_agent_cpu_usage_ratio";
pub const BUFFER_DROPPED_TOTAL: &str = "kestrel_agent_buffer_dropped_total";
pub const PROCESS_COUNT: &str = "kestrel_process_count";
pub const PROCESS_CPU_RATIO: &str = "kestrel_process_cpu_ratio";
pub const PROCESS_MEMORY_BYTES: &str = "kestrel_process_memory_bytes";
pub const SERVICE_UP: &str = "kestrel_service_up";

/// Every metric name the collectors are allowed to emit.
pub const DOCUMENTED: &[&str] = &[
    CPU_USAGE_RATIO,
    MEMORY_USED_BYTES,
    MEMORY_AVAILABLE_BYTES,
    MEMORY_TOTAL_BYTES,
    SWAP_USED_BYTES,
    SWAP_TOTAL_BYTES,
    LOAD1,
    LOAD5,
    LOAD15,
    FILESYSTEM_FREE_BYTES,
    FILESYSTEM_SIZE_BYTES,
    FILESYSTEM_USED_RATIO,
    DISK_READ_BYTES_TOTAL,
    DISK_WRITTEN_BYTES_TOTAL,
    NETWORK_RECEIVE_BYTES_TOTAL,
    NETWORK_TRANSMIT_BYTES_TOTAL,
    NETWORK_RECEIVE_PACKETS_TOTAL,
    NETWORK_TRANSMIT_PACKETS_TOTAL,
    NETWORK_RECEIVE_ERRORS_TOTAL,
    NETWORK_TRANSMIT_ERRORS_TOTAL,
    UPTIME_SECONDS,
    AGENT_MEMORY_BYTES,
    AGENT_CPU_USAGE_RATIO,
    BUFFER_DROPPED_TOTAL,
    PROCESS_COUNT,
    PROCESS_CPU_RATIO,
    PROCESS_MEMORY_BYTES,
    SERVICE_UP,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_doc_mentions_every_name() {
        let doc = include_str!("../../../docs/metrics.md");
        for name in DOCUMENTED {
            assert!(doc.contains(name), "{name} is missing from docs/metrics.md");
        }
    }
}
