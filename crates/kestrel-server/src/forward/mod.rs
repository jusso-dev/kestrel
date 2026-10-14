//! Outbound SIEM forwarding. Targets are operator-configured URLs. Tests use
//! local fakes and never open a connection to a real SIEM.

mod ocsf;

pub use ocsf::{api_activity, detection_finding, validate_class};

use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ForwardEvent {
    pub tenant_id: Uuid,
    pub kind: String,
    pub body: Value,
}

#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn forward(&self, ev: &ForwardEvent) -> Result<(), ForwardError>;
}

#[derive(Debug)]
pub struct ForwardError {
    message: String,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ForwardError {}

impl ForwardError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub struct WebhookForwarder {
    client: reqwest::Client,
    url: String,
    secret: String,
}

impl WebhookForwarder {
    pub fn new(url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            url: url.into(),
            secret: secret.into(),
        }
    }
}

#[async_trait]
impl Forwarder for WebhookForwarder {
    async fn forward(&self, ev: &ForwardEvent) -> Result<(), ForwardError> {
        let body =
            serde_json::to_vec(&ev.body).map_err(|err| ForwardError::new(err.to_string()))?;
        let signature = crate::notify::sign_body(self.secret.as_bytes(), &body);
        let response = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("x-kestrel-signature", signature)
            .body(body)
            .send()
            .await
            .map_err(|err| ForwardError::new(err.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ForwardError::new(format!(
                "forward status {}",
                response.status()
            )))
        }
    }
}

pub struct WedgetailForwarder {
    client: reqwest::Client,
    url: String,
    token: String,
}

impl WedgetailForwarder {
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            url: url.into(),
            token: token.into(),
        }
    }
}

#[async_trait]
impl Forwarder for WedgetailForwarder {
    async fn forward(&self, ev: &ForwardEvent) -> Result<(), ForwardError> {
        let line =
            serde_json::to_string(&ev.body).map_err(|err| ForwardError::new(err.to_string()))?;
        let response = self
            .client
            .post(&self.url)
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/x-ndjson")
            .body(format!("{line}\n"))
            .send()
            .await
            .map_err(|err| ForwardError::new(err.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ForwardError::new(format!(
                "wedgetail status {}",
                response.status()
            )))
        }
    }
}

pub fn rfc5424(hostname: &str, app: &str, msg: &str, ts: chrono::DateTime<chrono::Utc>) -> String {
    let stamp = ts.format("%Y-%m-%dT%H:%M:%SZ");
    format!("<134>1 {stamp} {hostname} {app} - - - {msg}")
}

pub fn octet_count(msg: &str) -> Vec<u8> {
    let mut out = format!("{} ", msg.len()).into_bytes();
    out.extend_from_slice(msg.as_bytes());
    out
}

pub async fn send_syslog(addr: std::net::SocketAddr, msg: &str) -> Result<(), ForwardError> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|err| ForwardError::new(err.to_string()))?;
    stream
        .write_all(&octet_count(msg))
        .await
        .map_err(|err| ForwardError::new(err.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ForwardJob {
    pub id: Uuid,
    pub status: String,
    pub attempts: i32,
    pub run_after: i64,
    pub last_error: Option<String>,
}

pub fn apply_forward_attempt(job: &mut ForwardJob, ok: bool, now: i64) {
    job.attempts += 1;
    if ok {
        job.status = "sent".to_string();
        job.last_error = None;
    } else if job.attempts >= 10 {
        job.status = "failed".to_string();
        job.last_error = Some("forward failed".to_string());
    } else {
        job.status = "pending".to_string();
        job.last_error = Some("forward failed".to_string());
        job.run_after = now.saturating_add(crate::notify::backoff_seconds(job.attempts));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn forward_reaches_syslog_and_wedgetail_without_blocking_retries() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/kestrel"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer wgi_test_token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"accepted":1,"skipped":0}"#),
            )
            .mount(&server)
            .await;
        let finding = detection_finding("disk", "web-1", "problem", "high");
        validate_class(&finding, 2004).unwrap();
        let audit = api_activity("host.create", "ops@example.com", "POST /api/v1/hosts");
        validate_class(&audit, 6003).unwrap();
        let wedge =
            WedgetailForwarder::new(format!("{}/v1/kestrel", server.uri()), "wgi_test_token");
        wedge
            .forward(&ForwardEvent {
                tenant_id: Uuid::nil(),
                kind: "problem".to_string(),
                body: finding,
            })
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::clone(&received);
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = socket.read(&mut buf).await {
                store.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let msg = rfc5424(
            "kestrel",
            "kestrel",
            "disk full",
            chrono::Utc.with_ymd_and_hms(2026, 10, 14, 0, 0, 0).unwrap(),
        );
        send_syslog(addr, &msg).await.unwrap();
        let ready = tokio::time::timeout(Duration::from_secs(2), async {
            while received.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(ready.is_ok());
        let bytes = received.lock().unwrap().clone();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("disk full"), "{text}");
        assert!(text.contains("<134>1"), "{text}");
        let mut job = ForwardJob {
            id: Uuid::from_u128(1),
            status: "pending".to_string(),
            attempts: 0,
            run_after: 0,
            last_error: None,
        };
        apply_forward_attempt(&mut job, false, 10);
        assert_eq!(job.status, "pending");
        assert!(job.run_after > 10);
    }
}
