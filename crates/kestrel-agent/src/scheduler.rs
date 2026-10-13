//! Run collectors on their own intervals and batch the samples.
//!
//! One task per collector ticks with `MissedTickBehavior::Skip`. Samples are
//! queued on an `mpsc` channel. The batcher flushes to the disk buffer every
//! 5 seconds, or sooner once 5000 samples are waiting.

use crate::buffer::Buffer;
use kestrel_checks::{Collector, BUFFER_DROPPED_TOTAL};
use kestrel_proto::v1::{self, Batch};
use kestrel_proto::Sample;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;

/// Flush a non-empty batch this long after its first sample.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// Flush immediately once this many collector samples are waiting.
pub const FLUSH_MAX_SAMPLES: usize = 5000;

/// Spawn one task per collector. Each task stops when `shutdown` changes.
pub fn spawn_collectors(
    collectors: Vec<Box<dyn Collector>>,
    tx: mpsc::Sender<Vec<Sample>>,
    shutdown: watch::Receiver<bool>,
) {
    for collector in collectors {
        let tx = tx.clone();
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut collector = collector;
            let period = collector.interval().max(Duration::from_millis(1));
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = interval.tick() => {
                        if *shutdown.borrow() {
                            break;
                        }
                        match collector.collect(unix_ms()) {
                            Ok(samples) if !samples.is_empty() => {
                                if tx.send(samples).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(
                                    collector = collector.name(),
                                    error = %err,
                                    "collector failed"
                                );
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Group samples into batches and append them to `buffer`.
pub async fn run_batcher(
    samples: mpsc::Receiver<Vec<Sample>>,
    buffer: Arc<Mutex<Buffer>>,
    agent_id: String,
    shutdown: watch::Receiver<bool>,
) {
    run_batcher_interval(samples, buffer, agent_id, shutdown, FLUSH_INTERVAL).await;
}

pub(crate) async fn run_batcher_interval(
    mut samples: mpsc::Receiver<Vec<Sample>>,
    buffer: Arc<Mutex<Buffer>>,
    agent_id: String,
    mut shutdown: watch::Receiver<bool>,
    flush_every: Duration,
) {
    let mut pending = Vec::new();
    let mut ticker = tokio::time::interval(flush_every.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // `interval` fires immediately. Consume that tick so the first time-based
    // flush is one period later.
    ticker.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                while let Ok(batch) = samples.try_recv() {
                    pending.extend(batch);
                }
                flush(&buffer, &agent_id, &mut pending);
                break;
            }
            incoming = samples.recv() => {
                match incoming {
                    Some(batch) => {
                        pending.extend(batch);
                        if pending.len() >= FLUSH_MAX_SAMPLES {
                            flush(&buffer, &agent_id, &mut pending);
                        }
                    }
                    None => {
                        flush(&buffer, &agent_id, &mut pending);
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                flush(&buffer, &agent_id, &mut pending);
            }
        }
    }
}

fn flush(buffer: &Mutex<Buffer>, agent_id: &str, pending: &mut Vec<Sample>) {
    if pending.is_empty() {
        return;
    }
    match write_batch(buffer, agent_id, pending) {
        Ok(()) => pending.clear(),
        Err(err) => tracing::error!(error = %err, "failed to append batch"),
    }
}

fn write_batch(buffer: &Mutex<Buffer>, agent_id: &str, pending: &[Sample]) -> std::io::Result<()> {
    let mut guard = lock_buffer(buffer);
    let dropped = guard.dropped();
    let mut samples: Vec<v1::Sample> = pending.iter().cloned().map(Into::into).collect();
    samples.push(v1::Sample {
        name: BUFFER_DROPPED_TOTAL.to_string(),
        labels: vec![],
        value: dropped as f64,
        timestamp_ms: unix_ms(),
    });
    let batch = Batch {
        agent_id: agent_id.to_string(),
        seq: 0,
        samples,
        checks: vec![],
        logs: vec![],
        inventory: None,
    };
    guard.append(&batch)
}

fn lock_buffer(buffer: &Mutex<Buffer>) -> std::sync::MutexGuard<'_, Buffer> {
    buffer.lock().unwrap_or_else(|err| err.into_inner())
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_checks::CollectError;
    use kestrel_proto::{decode_batch, DEFAULT_MAX_DECOMPRESSED};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kestrel-scheduler-{label}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn sample(value: f64) -> Sample {
        Sample {
            name: "kestrel_uptime_seconds".to_string(),
            labels: vec![],
            value,
            timestamp_ms: 5,
        }
    }

    struct TickCollector {
        interval: Duration,
        ticks: Arc<AtomicUsize>,
    }

    impl Collector for TickCollector {
        fn name(&self) -> &str {
            "tick"
        }

        fn interval(&self) -> Duration {
            self.interval
        }

        fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
            let tick = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(vec![Sample {
                name: "kestrel_uptime_seconds".to_string(),
                labels: vec![],
                value: tick as f64,
                timestamp_ms: now_ms,
            }])
        }
    }

    #[tokio::test]
    async fn scheduler_flushes_on_the_batch_interval() {
        assert_eq!(FLUSH_INTERVAL, Duration::from_secs(5));
        let dir = scratch("time");
        let buffer = Arc::new(Mutex::new(Buffer::open(&dir, 8 * 1024 * 1024).unwrap()));
        let (tx, rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let batch_buffer = buffer.clone();
        let task = tokio::spawn(async move {
            run_batcher_interval(
                rx,
                batch_buffer,
                "agent-1".to_string(),
                shutdown_rx,
                Duration::from_millis(50),
            )
            .await;
        });
        tokio::task::yield_now().await;
        tx.send(vec![sample(1.0), sample(2.0)]).await.unwrap();
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(
            lock_buffer(&buffer).peek().unwrap().is_none(),
            "a short batch should wait for the flush interval"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (seq, bytes) = lock_buffer(&buffer)
            .peek()
            .unwrap()
            .expect("batch should flush when the interval elapses");
        let decoded = decode_batch(&bytes, DEFAULT_MAX_DECOMPRESSED).unwrap();
        assert_eq!(seq, decoded.seq);
        assert_eq!(decoded.agent_id, "agent-1");
        assert_eq!(decoded.samples.len(), 3);
        assert_eq!(decoded.samples[2].name, BUFFER_DROPPED_TOTAL);
        assert_eq!(decoded.samples[2].value, 0.0);
        let _ = shutdown_tx.send(true);
        drop(tx);
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_flushes_at_five_thousand_samples() {
        let dir = scratch("count");
        let buffer = Arc::new(Mutex::new(Buffer::open(&dir, 64 * 1024 * 1024).unwrap()));
        let (tx, rx) = mpsc::channel(4);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let batch_buffer = buffer.clone();
        let task = tokio::spawn(async move {
            run_batcher(rx, batch_buffer, "agent-1".to_string(), shutdown_rx).await;
        });
        let samples = (0..FLUSH_MAX_SAMPLES).map(|i| sample(i as f64)).collect();
        tx.send(samples).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        let (_, bytes) = lock_buffer(&buffer)
            .peek()
            .unwrap()
            .expect("5000 samples flush without waiting");
        let decoded = decode_batch(&bytes, DEFAULT_MAX_DECOMPRESSED).unwrap();
        assert_eq!(decoded.samples.len(), FLUSH_MAX_SAMPLES + 1);
        drop(tx);
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_skips_missed_collector_ticks() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_collectors(
            vec![Box::new(TickCollector {
                interval: Duration::from_secs(10),
                ticks: ticks.clone(),
            })],
            tx,
            shutdown_rx,
        );
        let first = rx.recv().await.unwrap();
        assert_eq!(first.len(), 1);
        tokio::time::advance(Duration::from_secs(35)).await;
        let second = rx.recv().await.unwrap();
        assert_eq!(second.len(), 1);
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err());
        assert_eq!(ticks.load(Ordering::SeqCst), 2);
        let _ = shutdown_tx.send(true);
    }
}
