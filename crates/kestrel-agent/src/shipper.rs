//! Drain the on-disk buffer to `POST /api/v1/ingest`.
//!
//! A 2xx response acknowledges the head batch. `429` and `5xx`, and network
//! errors, wait with exponential backoff from 1 second up to 5 minutes and
//! 20 percent jitter. Any other `4xx` is logged and the batch is dropped.

use crate::buffer::Buffer;
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use url::Url;

const IDLE_POLL: Duration = Duration::from_millis(200);
const BACKOFF_BASE_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 5 * 60 * 1_000;

/// PEM material for an enrolled agent.
pub struct ClientIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
}

/// HTTP client that posts batches in buffer order.
pub struct Shipper {
    client: Arc<Mutex<reqwest::Client>>,
    ingest_url: Url,
}

/// The shipper could not be built.
#[derive(Debug)]
pub struct ShipError {
    message: String,
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ShipError {}

impl ShipError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Shipper {
    /// POST batches to `{server_url}/api/v1/ingest`.
    pub fn new(server_url: &Url) -> Result<Self, ShipError> {
        Ok(Self {
            client: Arc::new(Mutex::new(plain_client()?)),
            ingest_url: ingest_url(server_url)?,
        })
    }

    /// POST batches with a client certificate and the server's CA.
    pub fn with_identity(server_url: &Url, identity: &ClientIdentity) -> Result<Self, ShipError> {
        Ok(Self {
            client: Arc::new(Mutex::new(mtls_client(identity)?)),
            ingest_url: ingest_url(server_url)?,
        })
    }

    /// Swap the HTTP client after a certificate renewal.
    pub fn replace_client(&self, client: reqwest::Client) {
        *self.client.lock().unwrap_or_else(|err| err.into_inner()) = client;
    }

    /// Ship until `shutdown` is set. `sleep` waits out a backoff.
    ///
    /// `jitter` returns a factor in `0.8..=1.2`. The idle poll between empty
    /// reads uses the runtime clock so tests can record backoff delays only.
    pub async fn run<S, Fut, J>(
        &self,
        buffer: Arc<Mutex<Buffer>>,
        mut shutdown: watch::Receiver<bool>,
        sleep: S,
        mut jitter: J,
    ) where
        S: Fn(Duration) -> Fut + Send + Sync,
        Fut: Future<Output = ()> + Send,
        J: FnMut() -> f64 + Send,
    {
        tracing::info!(url = %self.ingest_url, "shipper started");
        let mut attempt = 0u32;
        loop {
            if *shutdown.borrow() {
                break;
            }
            let peeked = {
                let mut guard = lock_buffer(&buffer);
                if let Err(err) = guard.poll_sync() {
                    tracing::warn!(error = %err, "buffer sync failed");
                }
                match guard.peek() {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!(error = %err, "buffer peek failed");
                        None
                    }
                }
            };
            let Some((seq, bytes)) = peeked else {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = tokio::time::sleep(IDLE_POLL) => {}
                }
                continue;
            };
            let action = match self.post(bytes).await {
                Ok(status) if status.is_success() => Action::Ack,
                Ok(status) if status.is_client_error() && status.as_u16() != 429 => {
                    tracing::warn!(
                        seq,
                        status = status.as_u16(),
                        "dropping batch rejected by the server"
                    );
                    Action::Drop
                }
                Ok(status) => {
                    let delay = backoff_delay(attempt, jitter());
                    tracing::warn!(
                        seq,
                        status = status.as_u16(),
                        delay_ms = delay.as_millis() as u64,
                        "ingest asked for a retry"
                    );
                    Action::Retry(delay)
                }
                Err(err) => {
                    let delay = backoff_delay(attempt, jitter());
                    tracing::warn!(
                        seq,
                        error = %err,
                        delay_ms = delay.as_millis() as u64,
                        "ingest request failed"
                    );
                    Action::Retry(delay)
                }
            };
            match action {
                Action::Ack | Action::Drop => {
                    acknowledge(&buffer, seq);
                    attempt = 0;
                }
                Action::Retry(delay) => {
                    attempt = attempt.saturating_add(1);
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        _ = sleep(delay) => {}
                    }
                }
            }
        }
    }

    /// POST one body. `2xx` is success; the caller decides what to do with other statuses.
    pub async fn post_bytes(&self, bytes: Vec<u8>) -> Result<u16, ShipError> {
        self.post(bytes)
            .await
            .map(|status| status.as_u16())
            .map_err(|err| ShipError::new(err.to_string()))
    }

    async fn post(&self, bytes: Vec<u8>) -> Result<StatusCode, reqwest::Error> {
        let client = self
            .client
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        let response = client
            .post(self.ingest_url.clone())
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
            .await?;
        Ok(response.status())
    }
}

fn plain_client() -> Result<reqwest::Client, ShipError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| ShipError::new(err.to_string()))
}

/// Build a rustls client that presents `identity` and trusts its CA.
pub fn mtls_client(identity: &ClientIdentity) -> Result<reqwest::Client, ShipError> {
    let mut bundle = identity.cert_pem.clone();
    if !bundle.ends_with('\n') {
        bundle.push('\n');
    }
    bundle.push_str(&identity.key_pem);
    let tls_identity = reqwest::Identity::from_pem(bundle.as_bytes())
        .map_err(|err| ShipError::new(err.to_string()))?;
    let ca = reqwest::Certificate::from_pem(identity.ca_pem.as_bytes())
        .map_err(|err| ShipError::new(err.to_string()))?;
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .identity(tls_identity)
        .add_root_certificate(ca)
        .build()
        .map_err(|err| ShipError::new(err.to_string()))
}

enum Action {
    Ack,
    Drop,
    Retry(Duration),
}

/// `{server}/api/v1/ingest`, keeping any existing path prefix.
pub fn ingest_url(server: &Url) -> Result<Url, ShipError> {
    let mut base = server.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base.join("api/v1/ingest")
        .map_err(|err| ShipError::new(err.to_string()))
}

/// Backoff for `attempt` (starting at 0). `jitter` is clamped to `0.8..=1.2`.
///
/// The base delay starts at 1 second and doubles until it reaches 5 minutes.
pub fn backoff_delay(attempt: u32, jitter: f64) -> Duration {
    let shift = attempt.min(9);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let base_ms = BACKOFF_BASE_MS.saturating_mul(factor).min(BACKOFF_MAX_MS);
    let jitter = jitter.clamp(0.8, 1.2);
    let ms = (base_ms as f64 * jitter).round() as u64;
    Duration::from_millis(ms)
}

/// Uniform factor in `0.8..=1.2`, or `1.0` when the operating system RNG fails.
pub fn sample_jitter() -> f64 {
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        return 1.0;
    }
    let unit = (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64;
    0.8 + unit * 0.4
}

fn lock_buffer(buffer: &Mutex<Buffer>) -> std::sync::MutexGuard<'_, Buffer> {
    buffer.lock().unwrap_or_else(|err| err.into_inner())
}

fn acknowledge(buffer: &Mutex<Buffer>, seq: u64) {
    if let Err(err) = lock_buffer(buffer).ack(seq) {
        tracing::error!(seq, error = %err, "failed to acknowledge batch");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_proto::{decode_batch, v1, DEFAULT_MAX_DECOMPRESSED};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kestrel-shipper-{label}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn batch(note: &str) -> v1::Batch {
        v1::Batch {
            agent_id: "agent-ship".to_string(),
            seq: 0,
            samples: vec![],
            checks: vec![],
            logs: vec![v1::LogEvent {
                source: "test".to_string(),
                line: note.to_string(),
                timestamp_ms: 1,
                labels: vec![],
            }],
            inventory: None,
        }
    }

    fn seq_of(body: &[u8]) -> u64 {
        decode_batch(body, DEFAULT_MAX_DECOMPRESSED).unwrap().seq
    }

    async fn mount_status(server: &MockServer, status: u16, times: Option<u64>, priority: u8) {
        let response = ResponseTemplate::new(status);
        let mock = Mock::given(method("POST"))
            .and(path("/api/v1/ingest"))
            .respond_with(response)
            .with_priority(priority);
        let mock = match times {
            Some(times) => mock.up_to_n_times(times),
            None => mock,
        };
        mock.mount(server).await;
    }

    async fn drive_until(
        server: &MockServer,
        shutdown: &watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
        done: impl Fn(usize, &[u64]) -> bool,
    ) -> Vec<u64> {
        let start = std::time::Instant::now();
        let seqs = loop {
            let requests = server.received_requests().await.unwrap();
            let seqs: Vec<u64> = requests
                .iter()
                .map(|request| seq_of(&request.body))
                .collect();
            if done(seqs.len(), &seqs) {
                break seqs;
            }
            if start.elapsed() > Duration::from_secs(10) {
                panic!("timed out with seqs {seqs:?}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let _ = shutdown.send(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("shipper did not stop")
            .unwrap();
        seqs
    }

    fn spawn_shipper(
        server: &MockServer,
        buffer: Arc<Mutex<Buffer>>,
        delays: Arc<Mutex<Vec<Duration>>>,
    ) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let url = Url::parse(&server.uri()).unwrap();
        let shipper = Shipper::new(&url).unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let delays_sleep = delays.clone();
        let task = tokio::spawn(async move {
            shipper
                .run(
                    buffer,
                    shutdown_rx,
                    move |delay| {
                        delays_sleep.lock().unwrap().push(delay);
                        std::future::ready(())
                    },
                    || 1.0,
                )
                .await;
        });
        (shutdown_tx, task)
    }

    #[test]
    fn shipper_backoff_doubles_to_five_minutes_with_jitter() {
        assert_eq!(backoff_delay(0, 1.0), Duration::from_secs(1));
        assert_eq!(backoff_delay(1, 1.0), Duration::from_secs(2));
        assert_eq!(backoff_delay(8, 1.0), Duration::from_secs(256));
        assert_eq!(backoff_delay(9, 1.0), Duration::from_secs(300));
        assert_eq!(backoff_delay(20, 1.0), Duration::from_secs(300));
        assert_eq!(backoff_delay(0, 0.8), Duration::from_millis(800));
        assert_eq!(backoff_delay(0, 1.2), Duration::from_millis(1_200));
        assert_eq!(backoff_delay(1, 1.2), Duration::from_millis(2_400));
        assert_eq!(backoff_delay(9, 1.2), Duration::from_millis(360_000));
        let jitter = sample_jitter();
        assert!((0.8..=1.2).contains(&jitter), "{jitter}");
    }

    #[test]
    fn shipper_ingest_url_uses_the_server_root() {
        let url = Url::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!(
            ingest_url(&url).unwrap().as_str(),
            "http://127.0.0.1:8080/api/v1/ingest"
        );
        let url = Url::parse("https://kestrel.example:8443/prefix").unwrap();
        assert_eq!(
            ingest_url(&url).unwrap().as_str(),
            "https://kestrel.example:8443/prefix/api/v1/ingest"
        );
        let url = Url::parse("https://kestrel.example:8443/prefix/").unwrap();
        assert_eq!(
            ingest_url(&url).unwrap().as_str(),
            "https://kestrel.example:8443/prefix/api/v1/ingest"
        );
    }

    #[tokio::test]
    async fn shipper_retries_429_and_5xx_then_ships_in_order() {
        let server = MockServer::start().await;
        // Priority 1 is the highest. Each limited mock drops out after one hit.
        mount_status(&server, 503, Some(1), 1).await;
        mount_status(&server, 429, Some(1), 2).await;
        mount_status(&server, 200, None, 3).await;
        let dir = scratch("retry");
        let buffer = Arc::new(Mutex::new(Buffer::open(&dir, 8 * 1024 * 1024).unwrap()));
        {
            let mut guard = lock_buffer(&buffer);
            guard.append(&batch("one")).unwrap();
            guard.append(&batch("two")).unwrap();
        }
        let delays = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, task) = spawn_shipper(&server, buffer.clone(), delays.clone());
        let seqs = drive_until(&server, &shutdown, task, |_, seqs| {
            seqs.len() >= 4 && lock_buffer(&buffer).peek().unwrap().is_none()
        })
        .await;
        assert_eq!(seqs, vec![1, 1, 1, 2]);
        let recorded = delays.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![Duration::from_secs(1), Duration::from_secs(2)]
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests[0]
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shipper_drops_other_4xx() {
        let server = MockServer::start().await;
        mount_status(&server, 400, None, 1).await;
        let dir = scratch("drop");
        let buffer = Arc::new(Mutex::new(Buffer::open(&dir, 8 * 1024 * 1024).unwrap()));
        {
            let mut guard = lock_buffer(&buffer);
            guard.append(&batch("bad")).unwrap();
            guard.append(&batch("good")).unwrap();
        }
        let delays = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, task) = spawn_shipper(&server, buffer.clone(), delays.clone());
        let seqs = drive_until(&server, &shutdown, task, |_, _| {
            lock_buffer(&buffer).peek().unwrap().is_none()
        })
        .await;
        assert_eq!(seqs, vec![1, 2]);
        assert!(delays.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shipper_buffers_while_the_server_is_down_then_ships_in_order() {
        let down = MockServer::start().await;
        mount_status(&down, 503, None, 1).await;
        let dir = scratch("down");
        let buffer = Arc::new(Mutex::new(Buffer::open(&dir, 8 * 1024 * 1024).unwrap()));
        {
            let mut guard = lock_buffer(&buffer);
            guard.append(&batch("one")).unwrap();
            guard.append(&batch("two")).unwrap();
            guard.append(&batch("three")).unwrap();
        }
        let delays = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, task) = spawn_shipper(&down, buffer.clone(), delays.clone());
        drive_until(&down, &shutdown, task, |count, _| count >= 3).await;
        assert_eq!(lock_buffer(&buffer).pending_seqs(), vec![1, 2, 3]);

        let up = MockServer::start().await;
        mount_status(&up, 200, None, 1).await;
        let (shutdown, task) = spawn_shipper(&up, buffer.clone(), delays);
        let seqs = drive_until(&up, &shutdown, task, |_, _| {
            lock_buffer(&buffer).peek().unwrap().is_none()
        })
        .await;
        assert_eq!(seqs, vec![1, 2, 3]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
