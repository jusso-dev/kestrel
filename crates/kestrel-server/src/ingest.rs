//! Agent batch ingest: dedupe by sequence, label, and queue with backpressure.

use crate::store::{LabelledSample, MetricStore};
use kestrel_proto::v1::{self, Batch};
use kestrel_proto::{decode_batch, CheckState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, error::TrySendError};

pub const INGEST_QUEUE_CAPACITY: usize = 10_000;
pub const INGEST_BODY_LIMIT: usize = 8 * 1024 * 1024;
pub const LOG_RETENTION_DAYS: i64 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestDecision {
    Accepted,
    Duplicate,
    Overloaded,
    Rejected(String),
}

#[derive(Debug, Clone)]
pub struct PreparedBatch {
    pub agent_id: String,
    pub seq: u64,
    pub samples: Vec<LabelledSample>,
    pub checks: Vec<v1::CheckResult>,
    pub logs: Vec<v1::LogEvent>,
    pub inventory: Option<v1::Inventory>,
}

/// Bounded queue drained by writer tasks. A full queue returns 429.
pub struct IngestQueue {
    seqs: Mutex<HashMap<String, u64>>,
    tx: mpsc::Sender<Vec<LabelledSample>>,
}

impl IngestQueue {
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<Vec<LabelledSample>>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                seqs: Mutex::new(HashMap::new()),
                tx,
            },
            rx,
        )
    }

    pub fn remember(&self, agent_id: &str, seq: u64) {
        let mut seqs = self.seqs.lock().unwrap_or_else(|err| err.into_inner());
        let entry = seqs.entry(agent_id.to_string()).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }

    pub fn last_seq(&self, agent_id: &str) -> u64 {
        self.seqs
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(agent_id)
            .copied()
            .unwrap_or(0)
    }

    /// Accept `seq` only when it is newer than the last accepted sequence.
    /// The sequence is stored only after the queue accepts the samples.
    pub fn submit(&self, agent_id: &str, seq: u64, samples: Vec<LabelledSample>) -> IngestDecision {
        let mut seqs = self.seqs.lock().unwrap_or_else(|err| err.into_inner());
        let last = seqs.get(agent_id).copied().unwrap_or(0);
        if seq == 0 || seq <= last {
            return IngestDecision::Duplicate;
        }
        match self.tx.try_send(samples) {
            Ok(()) => {
                seqs.insert(agent_id.to_string(), seq);
                IngestDecision::Accepted
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => IngestDecision::Overloaded,
        }
    }
}

/// Drain queued samples into `store`, flushing every `flush_after` samples or
/// when the channel is idle.
pub async fn run_writer(
    mut rx: mpsc::Receiver<Vec<LabelledSample>>,
    store: Arc<dyn MetricStore>,
    flush_after: usize,
) {
    let mut pending = Vec::new();
    loop {
        let incoming = if pending.is_empty() {
            rx.recv().await
        } else {
            match tokio::time::timeout(std::time::Duration::from_millis(20), rx.recv()).await {
                Ok(value) => value,
                Err(_) => {
                    flush(&store, &mut pending).await;
                    continue;
                }
            }
        };
        match incoming {
            Some(mut samples) => {
                pending.append(&mut samples);
                if pending.len() >= flush_after.max(1) {
                    flush(&store, &mut pending).await;
                }
            }
            None => {
                flush(&store, &mut pending).await;
                break;
            }
        }
    }
}

async fn flush(store: &Arc<dyn MetricStore>, pending: &mut Vec<LabelledSample>) {
    if pending.is_empty() {
        return;
    }
    let mut delay = std::time::Duration::from_millis(100);
    loop {
        match store.write(pending.clone()).await {
            Ok(()) => {
                pending.clear();
                return;
            }
            Err(err) => tracing::warn!(error=%err,"metric write failed; retaining batch for retry"),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(std::time::Duration::from_secs(30));
    }
}

pub fn prepare_batch(
    bytes: &[u8],
    tenant: &str,
    host: &str,
    agent: &str,
) -> Result<PreparedBatch, IngestDecision> {
    let batch = decode_batch(bytes, INGEST_BODY_LIMIT)
        .map_err(|err| IngestDecision::Rejected(format!("could not decode batch: {err}")))?;
    if batch.samples.len() > 100_000
        || batch.checks.len() > 10_000
        || batch.logs.len() > 10_000
        || batch.samples.iter().any(|sample| sample.labels.len() > 30)
    {
        return Err(IngestDecision::Rejected(
            "batch has too many observations or labels".to_string(),
        ));
    }
    Ok(label_batch(batch, tenant, host, agent))
}

pub fn label_batch(batch: Batch, tenant: &str, host: &str, agent: &str) -> PreparedBatch {
    let mut samples = Vec::new();
    for sample in &batch.samples {
        samples.push(label_sample(
            sample.name.clone(),
            sample.labels.clone(),
            sample.value,
            sample.timestamp_ms,
            tenant,
            host,
            agent,
        ));
    }
    let seen_ms = samples
        .last()
        .map(|sample| sample.timestamp_ms)
        .unwrap_or(0);
    if seen_ms > 0 {
        samples.push(LabelledSample {
            name: "kestrel_agent_last_seen_timestamp".to_string(),
            labels: base_labels(tenant, host, agent),
            value: (seen_ms / 1000) as f64,
            timestamp_ms: seen_ms,
        });
    }
    for check in &batch.checks {
        let mut labels = base_labels(tenant, host, agent);
        labels.push(("check".to_string(), check.check_id.clone()));
        samples.push(LabelledSample {
            name: "kestrel_check_state".to_string(),
            labels,
            value: f64::from(check.state),
            timestamp_ms: check.timestamp_ms,
        });
        if let Ok(perf) = kestrel_checks::parse_perfdata(&check.perfdata) {
            for point in perf {
                let mut labels = base_labels(tenant, host, agent);
                labels.push(("check".to_string(), check.check_id.clone()));
                labels.push(("label".to_string(), point.label));
                labels.push(("uom".to_string(), point.uom));
                samples.push(LabelledSample {
                    name: "kestrel_check_perf".to_string(),
                    labels,
                    value: point.value,
                    timestamp_ms: check.timestamp_ms,
                });
            }
        }
    }
    PreparedBatch {
        agent_id: agent.to_string(),
        seq: batch.seq,
        samples,
        checks: batch.checks,
        logs: batch.logs,
        inventory: batch.inventory,
    }
}

fn label_sample(
    name: String,
    labels: Vec<v1::Label>,
    value: f64,
    timestamp_ms: i64,
    tenant: &str,
    host: &str,
    agent: &str,
) -> LabelledSample {
    let mut out = base_labels(tenant, host, agent);
    for label in labels {
        if matches!(
            label.name.as_str(),
            "tenant" | "host" | "agent" | "__name__"
        ) {
            continue;
        }
        out.push((label.name, label.value));
    }
    LabelledSample {
        name,
        labels: out,
        value,
        timestamp_ms,
    }
}

fn base_labels(tenant: &str, host: &str, agent: &str) -> Vec<(String, String)> {
    vec![
        ("tenant".to_string(), tenant.to_string()),
        ("host".to_string(), host.to_string()),
        ("agent".to_string(), agent.to_string()),
    ]
}

pub fn check_state_name(state: i32) -> &'static str {
    match CheckState::from_exit_code(state) {
        CheckState::Ok => "ok",
        CheckState::Warning => "warning",
        CheckState::Critical => "critical",
        CheckState::Unknown => "unknown",
    }
}

/// Partition name for a unix-millisecond timestamp. Daily, UTC.
pub fn log_partition_name(timestamp_ms: i64) -> String {
    use chrono::Datelike;
    let secs = timestamp_ms.div_euclid(1000);
    let date = chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .date_naive();
    format!(
        "log_events_{:04}_{:02}_{:02}",
        date.year(),
        date.month(),
        date.day()
    )
}

pub fn partition_is_expired(name: &str, today: &str, keep_days: i64) -> bool {
    let Some(date) = name.strip_prefix("log_events_") else {
        return false;
    };
    let Some(today) = today.strip_prefix("log_events_") else {
        return false;
    };
    let Some(age) = day_number(today)
        .zip(day_number(date))
        .map(|(now, then)| now - then)
    else {
        return false;
    };
    age > keep_days
}

fn day_number(yyyymmdd: &str) -> Option<i64> {
    use chrono::Datelike;
    chrono::NaiveDate::parse_from_str(yyyymmdd, "%Y_%m_%d")
        .ok()
        .map(|date| i64::from(date.num_days_from_ce()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use kestrel_proto::encode_batch;

    fn batch(seq: u64, value: f64) -> Vec<u8> {
        encode_batch(&v1::Batch {
            agent_id: "agent-1".to_string(),
            seq,
            samples: vec![v1::Sample {
                name: "kestrel_memory_used_bytes".to_string(),
                labels: vec![v1::Label {
                    name: "host".to_string(),
                    value: "spoofed".to_string(),
                }],
                value,
                timestamp_ms: 1_700_000_000_000,
            }],
            checks: vec![v1::CheckResult {
                check_id: "disk".to_string(),
                state: 1,
                output: "85%".to_string(),
                perfdata: "used=85%;90;95;0;100".to_string(),
                timestamp_ms: 1_700_000_000_000,
            }],
            logs: vec![v1::LogEvent {
                source: "/var/log/syslog".to_string(),
                line: "hello".to_string(),
                timestamp_ms: 1_700_000_000_000,
                labels: vec![],
            }],
            inventory: None,
        })
    }

    #[test]
    fn log_retention_uses_calendar_days_across_months_and_leap_years() {
        assert!(!partition_is_expired(
            "log_events_2024_02_29",
            "log_events_2024_03_07",
            7
        ));
        assert!(partition_is_expired(
            "log_events_2024_02_28",
            "log_events_2024_03_07",
            7
        ));
        assert!(!partition_is_expired(
            "log_events_2024_02_31",
            "log_events_2024_03_07",
            7
        ));
    }

    #[test]
    fn ingest_duplicate_seq_is_ignored_and_full_queue_is_overload() {
        let (queue, _rx) = IngestQueue::new(1);
        let first = prepare_batch(&batch(1, 1.0), "tenant-a", "web-1", "agent-1").unwrap();
        assert_eq!(
            queue.submit("agent-1", first.seq, first.samples.clone()),
            IngestDecision::Accepted
        );
        let duplicate = prepare_batch(&batch(1, 2.0), "tenant-a", "web-1", "agent-1").unwrap();
        assert_eq!(
            queue.submit("agent-1", duplicate.seq, duplicate.samples),
            IngestDecision::Duplicate
        );
        let next = prepare_batch(&batch(2, 3.0), "tenant-a", "web-1", "agent-1").unwrap();
        assert_eq!(
            queue.submit("agent-1", next.seq, next.samples),
            IngestDecision::Overloaded
        );
        assert_eq!(queue.last_seq("agent-1"), 1);
    }

    #[test]
    fn ingest_labels_tenant_host_and_agent_and_check_state() {
        let prepared = prepare_batch(&batch(4, 8.0), "tenant-a", "web-1", "agent-1").unwrap();
        let memory = &prepared.samples[0];
        assert!(memory
            .labels
            .iter()
            .any(|(name, value)| name == "tenant" && value == "tenant-a"));
        assert!(memory
            .labels
            .iter()
            .any(|(name, value)| name == "host" && value == "web-1"));
        assert!(memory
            .labels
            .iter()
            .any(|(name, value)| name == "agent" && value == "agent-1"));
        assert!(!memory
            .labels
            .iter()
            .any(|(name, value)| name == "host" && value == "spoofed"));
        assert!(prepared
            .samples
            .iter()
            .any(|sample| sample.name == "kestrel_check_state"));
        assert_eq!(prepared.logs.len(), 1);
        assert_eq!(
            log_partition_name(1_700_000_000_000),
            "log_events_2023_11_14"
        );
        assert!(partition_is_expired(
            "log_events_2023_11_01",
            "log_events_2023_11_14",
            LOG_RETENTION_DAYS
        ));
        assert!(!partition_is_expired(
            "log_events_2023_11_10",
            "log_events_2023_11_14",
            LOG_RETENTION_DAYS
        ));
    }

    #[tokio::test]
    async fn ingest_writer_flushes_to_the_store() {
        let (queue, rx) = IngestQueue::new(8);
        let store = Arc::new(MemoryStore::new());
        let writer = {
            let store = Arc::clone(&store) as Arc<dyn MetricStore>;
            tokio::spawn(run_writer(rx, store, 1))
        };
        let prepared = prepare_batch(&batch(1, 5.0), "t", "h", "a").unwrap();
        assert_eq!(
            queue.submit("a", prepared.seq, prepared.samples),
            IngestDecision::Accepted
        );
        let ready = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while store.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(ready.is_ok(), "writer did not flush");
        drop(queue);
        writer.await.unwrap();
    }

    #[test]
    fn ingest_decode_one_thousand_samples() {
        let samples = (0..1000)
            .map(|index| v1::Sample {
                name: "kestrel_memory_used_bytes".to_string(),
                labels: vec![],
                value: index as f64,
                timestamp_ms: 1_700_000_000_000 + index,
            })
            .collect();
        let bytes = encode_batch(&v1::Batch {
            agent_id: "bench".to_string(),
            seq: 1,
            samples,
            checks: vec![],
            logs: vec![],
            inventory: None,
        });
        let prepared = prepare_batch(&bytes, "t", "h", "a").unwrap();
        assert!(prepared.samples.len() >= 1000);
    }
}
