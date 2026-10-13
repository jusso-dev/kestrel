//! Per-interface network counters. Totals are monotonic; the server rates them.

use crate::metrics::{
    NETWORK_RECEIVE_BYTES_TOTAL, NETWORK_RECEIVE_ERRORS_TOTAL, NETWORK_RECEIVE_PACKETS_TOTAL,
    NETWORK_TRANSMIT_BYTES_TOTAL, NETWORK_TRANSMIT_ERRORS_TOTAL, NETWORK_TRANSMIT_PACKETS_TOTAL,
};
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::time::Duration;
use sysinfo::Networks;

pub struct NetworkCollector {
    networks: Networks,
    interval: Duration,
}

impl NetworkCollector {
    pub fn new() -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &str {
        "network"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        self.networks.refresh();
        let mut samples = Vec::new();
        for (iface, data) in &self.networks {
            let labels = [("iface", iface.as_str())];
            samples.push(sample(
                NETWORK_RECEIVE_BYTES_TOTAL,
                &labels,
                data.total_received() as f64,
                now_ms,
            ));
            samples.push(sample(
                NETWORK_TRANSMIT_BYTES_TOTAL,
                &labels,
                data.total_transmitted() as f64,
                now_ms,
            ));
            samples.push(sample(
                NETWORK_RECEIVE_PACKETS_TOTAL,
                &labels,
                data.total_packets_received() as f64,
                now_ms,
            ));
            samples.push(sample(
                NETWORK_TRANSMIT_PACKETS_TOTAL,
                &labels,
                data.total_packets_transmitted() as f64,
                now_ms,
            ));
            samples.push(sample(
                NETWORK_RECEIVE_ERRORS_TOTAL,
                &labels,
                data.total_errors_on_received() as f64,
                now_ms,
            ));
            samples.push(sample(
                NETWORK_TRANSMIT_ERRORS_TOTAL,
                &labels,
                data.total_errors_on_transmitted() as f64,
                now_ms,
            ));
        }
        Ok(samples)
    }
}
