//! Notification channels. HTTP targets in tests are local fakes. Nothing in
//! the test suite contacts Slack, Teams, PagerDuty, or a public SMTP server.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use minijinja::{context, Environment};
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

const DEFAULT_TEMPLATE: &str = include_str!("templates/default.j2");
const MAX_ATTEMPTS: i32 = 10;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct NotifyError {
    message: String,
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NotifyError {}

impl NotifyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rendered {
    pub subject: String,
    pub body: String,
    pub problem_id: String,
    pub status: String,
}

#[async_trait]
pub trait Notifier: Send + Sync {
    fn kind(&self) -> &str;
    async fn send(&self, msg: &Rendered, target: &Value) -> Result<(), NotifyError>;
}

pub fn render(
    problem: &str,
    host: &str,
    trigger: &str,
    value: &str,
    url: &str,
    status: &str,
) -> Result<Rendered, NotifyError> {
    let mut env = Environment::new();
    env.add_template("default", DEFAULT_TEMPLATE)
        .map_err(|err| NotifyError::new(err.to_string()))?;
    let template = env
        .get_template("default")
        .map_err(|err| NotifyError::new(err.to_string()))?;
    let body = template
        .render(context! {
            problem => context! { name => problem, status => status },
            host => host,
            trigger => trigger,
            value => value,
            url => url,
        })
        .map_err(|err| NotifyError::new(err.to_string()))?;
    Ok(Rendered {
        subject: format!("{problem} on {host}"),
        body,
        problem_id: problem.to_string(),
        status: status.to_string(),
    })
}

pub fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(body);
    format!(
        "sha256={}",
        data_encoding::HEXLOWER.encode(mac.finalize().into_bytes().as_slice())
    )
}

pub struct HttpNotifier {
    client: reqwest::Client,
}

impl HttpNotifier {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }
}

impl Default for HttpNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Notifier for HttpNotifier {
    fn kind(&self) -> &str {
        "http"
    }

    async fn send(&self, msg: &Rendered, target: &Value) -> Result<(), NotifyError> {
        let kind = target
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("webhook");
        match kind {
            "slack" => {
                post_json(
                    &self.client,
                    required(target, "webhook_url")?,
                    &slack_body(msg),
                    None,
                )
                .await
            }
            "teams" => {
                post_json(
                    &self.client,
                    required(target, "webhook_url")?,
                    &teams_body(msg),
                    None,
                )
                .await
            }
            "pagerduty" => {
                let url = target
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("https://events.pagerduty.com/v2/enqueue");
                post_json(
                    &self.client,
                    url,
                    &pagerduty_body(msg, required(target, "routing_key")?),
                    None,
                )
                .await
            }
            _ => {
                let url = required(target, "url")?;
                let secret = target.get("secret").and_then(Value::as_str).unwrap_or("");
                let body = serde_json::to_vec(&webhook_body(msg))
                    .map_err(|err| NotifyError::new(err.to_string()))?;
                let signature = sign_body(secret.as_bytes(), &body);
                let response = self
                    .client
                    .post(url)
                    .header("content-type", "application/json")
                    .header("x-kestrel-signature", signature)
                    .body(body)
                    .send()
                    .await
                    .map_err(|err| NotifyError::new(err.to_string()))?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(NotifyError::new(format!(
                        "webhook status {}",
                        response.status()
                    )))
                }
            }
        }
    }
}

fn slack_body(msg: &Rendered) -> Value {
    json!({
        "blocks": [{
            "type": "section",
            "text": { "type": "mrkdwn", "text": msg.body }
        }]
    })
}

fn teams_body(msg: &Rendered) -> Value {
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [{ "type": "TextBlock", "text": msg.body, "wrap": true }]
            }
        }]
    })
}

fn pagerduty_body(msg: &Rendered, routing_key: &str) -> Value {
    let action = if msg.status == "resolved" {
        "resolve"
    } else {
        "trigger"
    };
    json!({
        "routing_key": routing_key,
        "event_action": action,
        "dedup_key": msg.problem_id,
        "payload": {
            "summary": msg.subject,
            "source": "kestrel",
            "severity": "error"
        }
    })
}

fn webhook_body(msg: &Rendered) -> Value {
    json!({
        "problem_id": msg.problem_id,
        "status": msg.status,
        "subject": msg.subject,
        "body": msg.body
    })
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    _signature: Option<&str>,
) -> Result<(), NotifyError> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|err| NotifyError::new(err.to_string()))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(NotifyError::new(format!(
            "notify status {}",
            response.status()
        )))
    }
}

fn required<'a>(target: &'a Value, key: &str) -> Result<&'a str, NotifyError> {
    target
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| NotifyError::new(format!("missing {key}")))
}

/// SMTP delivery. Tests use [`RecordingMail`] and never open a socket.
pub struct SmtpMail;

#[async_trait]
impl Notifier for SmtpMail {
    fn kind(&self) -> &str {
        "email"
    }

    async fn send(&self, msg: &Rendered, target: &Value) -> Result<(), NotifyError> {
        send_smtp(msg, target).await
    }
}

pub async fn send_smtp(msg: &Rendered, target: &Value) -> Result<(), NotifyError> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let to = required(target, "to")?;
    let from = target
        .get("from")
        .and_then(Value::as_str)
        .unwrap_or("kestrel@localhost");
    let host = required(target, "smtp_host")?;
    let port = target
        .get("smtp_port")
        .and_then(Value::as_u64)
        .unwrap_or(1025) as u16;
    let email = Message::builder()
        .from(
            from.parse()
                .map_err(|err: lettre::address::AddressError| NotifyError::new(err.to_string()))?,
        )
        .to(to
            .parse()
            .map_err(|err: lettre::address::AddressError| NotifyError::new(err.to_string()))?)
        .subject(&msg.subject)
        .header(ContentType::TEXT_PLAIN)
        .body(msg.body.clone())
        .map_err(|err| NotifyError::new(err.to_string()))?;
    let starttls = target
        .get("starttls")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut builder = if starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|err| NotifyError::new(err.to_string()))?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
    };
    builder = builder.port(port);
    if let (Some(user), Some(password)) = (
        target.get("username").and_then(Value::as_str),
        target.get("password").and_then(Value::as_str),
    ) {
        builder = builder.credentials(Credentials::new(user.to_string(), password.to_string()));
    }
    builder
        .build()
        .send(email)
        .await
        .map(|_| ())
        .map_err(|err| NotifyError::new(err.to_string()))
}

#[derive(Default)]
pub struct RecordingMail {
    pub sent: Mutex<Vec<Rendered>>,
}

#[async_trait]
impl Notifier for RecordingMail {
    fn kind(&self) -> &str {
        "email"
    }

    async fn send(&self, msg: &Rendered, _target: &Value) -> Result<(), NotifyError> {
        self.sent
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(msg.clone());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NotifyJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: String,
    pub attempts: i32,
    pub run_after: i64,
    pub last_error: Option<String>,
    pub payload: Value,
}

pub fn backoff_seconds(attempts: i32) -> i64 {
    let shift = attempts.clamp(0, 8) as u32;
    2_i64.saturating_pow(shift).min(3_600)
}

pub fn apply_attempt(job: &mut NotifyJob, result: Result<(), String>, now: i64) {
    job.attempts += 1;
    match result {
        Ok(()) => {
            job.status = "sent".to_string();
            job.last_error = None;
        }
        Err(err) => {
            job.last_error = Some(err);
            if job.attempts >= MAX_ATTEMPTS {
                job.status = "failed".to_string();
            } else {
                job.status = "pending".to_string();
                job.run_after = now.saturating_add(backoff_seconds(job.attempts));
            }
        }
    }
}

pub fn claim_due(jobs: &mut [NotifyJob], now: i64, limit: usize) -> Vec<Uuid> {
    let mut claimed = Vec::new();
    for job in jobs.iter_mut() {
        if claimed.len() >= limit {
            break;
        }
        if job.status == "pending" && job.run_after <= now {
            job.status = "running".to_string();
            claimed.push(job.id);
        }
    }
    claimed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(status: &str) -> Rendered {
        render(
            "disk full",
            "web-1",
            "disk",
            "95",
            "https://kestrel.example/problems/1",
            status,
        )
        .unwrap()
    }

    #[test]
    fn notify_webhook_signature_matches_the_documented_example() {
        let body = br#"{"hello":"kestrel"}"#;
        assert_eq!(
            sign_body(b"docs-example-secret", body),
            "sha256=3edb78dd97c282d06b0f563a20febacec404e7dc935309850197a003d2b20344"
        );
    }

    #[tokio::test]
    async fn notify_channels_deliver_and_pagerduty_resolves() {
        let server = wiremock::MockServer::start().await;
        for path in ["/slack", "/teams", "/hook", "/pagerduty"] {
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path(path))
                .respond_with(wiremock::ResponseTemplate::new(200))
                .mount(&server)
                .await;
        }
        let notifier = HttpNotifier::new();
        let opened = message("problem");
        notifier
            .send(
                &opened,
                &json!({"kind": "slack", "webhook_url": format!("{}/slack", server.uri())}),
            )
            .await
            .unwrap();
        notifier
            .send(
                &opened,
                &json!({"kind": "teams", "webhook_url": format!("{}/teams", server.uri())}),
            )
            .await
            .unwrap();
        notifier
            .send(&opened, &json!({"kind": "webhook", "url": format!("{}/hook", server.uri()), "secret": "docs-example-secret"}))
            .await
            .unwrap();
        let resolved = message("resolved");
        notifier
            .send(
                &resolved,
                &json!({"kind": "pagerduty", "routing_key": "rk", "url": format!("{}/pagerduty", server.uri())}),
            )
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let hook = requests
            .iter()
            .find(|request| request.url.path() == "/hook")
            .unwrap();
        let signature = hook
            .headers
            .get("x-kestrel-signature")
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(signature.starts_with("sha256="));
        let pager = requests
            .iter()
            .find(|request| request.url.path() == "/pagerduty")
            .unwrap();
        let body: Value = serde_json::from_slice(&pager.body).unwrap();
        assert_eq!(body["event_action"], "resolve");
        assert_eq!(body["dedup_key"], "disk full");
        let mail = RecordingMail::default();
        mail.send(&opened, &json!({"to": "ops@example.com"}))
            .await
            .unwrap();
        assert_eq!(mail.sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn notify_jobs_retry_and_survive_a_restart() {
        let mut jobs = vec![NotifyJob {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            status: "pending".to_string(),
            attempts: 0,
            run_after: 0,
            last_error: None,
            payload: json!({}),
        }];
        let claimed = claim_due(&mut jobs, 10, 50);
        assert_eq!(claimed, vec![Uuid::from_u128(1)]);
        apply_attempt(&mut jobs[0], Err("down".to_string()), 10);
        assert_eq!(jobs[0].status, "pending");
        assert!(jobs[0].run_after > 10);
        assert_eq!(jobs[0].last_error.as_deref(), Some("down"));
        let restored = jobs.clone();
        assert_eq!(restored[0].attempts, 1);
        jobs[0].status = "pending".to_string();
        jobs[0].attempts = 9;
        jobs[0].run_after = 0;
        let _ = claim_due(&mut jobs, 100, 50);
        apply_attempt(&mut jobs[0], Err("still down".to_string()), 100);
        assert_eq!(jobs[0].status, "failed");
        assert_eq!(jobs[0].attempts, 10);
    }
}
