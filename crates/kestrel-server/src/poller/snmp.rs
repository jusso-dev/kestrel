//! SNMP v2c and v3 polling. Credentials are supplied by the caller and are not
//! logged. The integration test against snmpsim is ignored unless that
//! simulator is running.

use crate::config_compile::{template_from_yaml, TemplateDoc};
use async_trait::async_trait;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const IF_TABLE: &str = "1.3.6.1.2.1.2.2.1";
pub const IF_X_TABLE: &str = "1.3.6.1.2.1.31.1.1.1";
pub const DEFAULT_PERMITS: usize = 256;

#[derive(Debug)]
pub struct PollError {
    message: String,
}

impl std::fmt::Display for PollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PollError {}

impl PollError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnmpTarget {
    pub addr: String,
    pub version: SnmpVersion,
}

#[derive(Clone)]
pub enum SnmpVersion {
    V2c {
        community: String,
    },
    V3 {
        user: String,
        auth: String,
        privacy: String,
    },
}

impl std::fmt::Debug for SnmpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::V2c { .. } => "V2c { credentials: [redacted] }",
            Self::V3 { .. } => "V3 { credentials: [redacted] }",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnmpVar {
    pub oid: String,
    pub value: String,
}

#[async_trait]
pub trait SnmpPoller: Send + Sync {
    async fn get(&self, target: &SnmpTarget, oid: &str) -> Result<SnmpVar, PollError>;
    async fn walk(&self, target: &SnmpTarget, oid: &str) -> Result<Vec<SnmpVar>, PollError>;
}

pub struct TimeoutPool {
    permits: Arc<Semaphore>,
}

impl TimeoutPool {
    pub fn new(permits: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits.max(1))),
        }
    }

    /// Run `work` while holding one permit. A timeout drops the permit so
    /// other devices are not stuck behind it.
    pub async fn run<T>(
        &self,
        timeout: Duration,
        work: impl std::future::Future<Output = T>,
    ) -> Result<T, PollError> {
        let permit = self.acquire(timeout).await?;
        let result = match tokio::time::timeout(timeout, work).await {
            Ok(value) => Ok(value),
            Err(_) => Err(PollError::new("snmp timed out")),
        };
        drop(permit);
        result
    }

    async fn acquire(&self, timeout: Duration) -> Result<OwnedSemaphorePermit, PollError> {
        match tokio::time::timeout(timeout, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(PollError::new("snmp poller is closed")),
            Err(_) => Err(PollError::new("snmp timed out waiting for a permit")),
        }
    }
}

pub struct BlockingPoller;

#[async_trait]
impl SnmpPoller for BlockingPoller {
    async fn get(&self, target: &SnmpTarget, oid: &str) -> Result<SnmpVar, PollError> {
        let target = target.clone();
        let oid = oid.to_string();
        run_blocking(move || session_get(&target, &oid)).await
    }

    async fn walk(&self, target: &SnmpTarget, oid: &str) -> Result<Vec<SnmpVar>, PollError> {
        let target = target.clone();
        let oid = oid.to_string();
        run_blocking(move || session_walk(&target, &oid)).await
    }
}

async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, PollError> + Send + 'static,
) -> Result<T, PollError> {
    let permit = blocking_permit().await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    // snmp2's inline packet buffers and v3 session initialization exceed a
    // default Tokio worker stack in debug builds. Isolate socket work on a
    // sized stack, retaining the concurrency permit even if its caller cancels.
    std::thread::Builder::new()
        .name("kestrel-snmp".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let _permit = permit;
            let _ = tx.send(work());
        })
        .map_err(|_| PollError::new("could not start SNMP worker"))?;
    rx.await.map_err(|_| PollError::new("SNMP worker failed"))?
}

async fn blocking_permit() -> Result<OwnedSemaphorePermit, PollError> {
    // A cancelled caller must not release its worker's permit while a socket
    // operation is still running, otherwise timed-out walks evade the cap.
    static LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
    LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(DEFAULT_PERMITS)))
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| PollError::new("SNMP worker pool closed"))
}

#[allow(dead_code)]
fn session_get(target: &SnmpTarget, oid: &str) -> Result<SnmpVar, PollError> {
    let mut session = open_session(target)?;
    let parsed = parse_oid(oid)?;
    session_request(&mut session, &parsed, false)?
        .ok_or_else(|| PollError::new("OID has no supported value"))
}

fn session_request(
    session: &mut snmp2::SyncSession,
    oid: &snmp2::Oid<'_>,
    next: bool,
) -> Result<Option<SnmpVar>, PollError> {
    for attempt in 0..3 {
        let result = if next {
            session.getnext(oid)
        } else {
            session.get(oid)
        };
        match result {
            Ok(mut pdu) => {
                if pdu.error_status != 0 {
                    return Err(PollError::new("device rejected SNMP request"));
                }
                let Some((oid, value)) = pdu.varbinds.next() else {
                    return Ok(None);
                };
                return Ok(value_text(value).map(|value| SnmpVar {
                    oid: oid.to_string(),
                    value,
                }));
            }
            // snmp2 updates engine boots/time from authenticated reports and
            // explicitly requires retrying the PDU after AuthUpdated.
            Err(snmp2::Error::AuthUpdated) if attempt < 2 => continue,
            Err(err) => return Err(PollError::new(err.to_string())),
        }
    }
    Err(PollError::new("SNMP security state did not settle"))
}

#[allow(dead_code)]
fn session_walk(target: &SnmpTarget, root: &str) -> Result<Vec<SnmpVar>, PollError> {
    let mut session = open_session(target)?;
    let mut current = parse_oid(root)?;
    let mut rows = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    for _ in 0..10_000 {
        if Instant::now() >= deadline {
            return Err(PollError::new("SNMP walk exceeded its deadline"));
        }
        let Some(row) = session_request(&mut session, &current, true)? else {
            break;
        };
        let next = row.oid.clone();
        if !(next == root || next.starts_with(&format!("{root}.")))
            || oid_parts(&next) <= oid_parts(&current.to_string())
        {
            break;
        }
        rows.push(row);
        current = parse_oid(&next)?;
    }
    Ok(rows)
}

fn oid_parts(oid: &str) -> Vec<u64> {
    oid.split('.').filter_map(|p| p.parse().ok()).collect()
}

fn value_text(value: snmp2::Value<'_>) -> Option<String> {
    use snmp2::Value;
    Some(match value {
        Value::Integer(v) => v.to_string(),
        Value::Counter32(v) | Value::Unsigned32(v) | Value::Timeticks(v) => v.to_string(),
        Value::Counter64(v) => v.to_string(),
        Value::Boolean(v) => if v { "1" } else { "0" }.into(),
        Value::OctetString(v) => String::from_utf8_lossy(v).into_owned(),
        Value::ObjectIdentifier(v) => v.to_string(),
        Value::IpAddress(v) => std::net::Ipv4Addr::from(v).to_string(),
        _ => return None,
    })
}

#[allow(dead_code)]
fn open_session(target: &SnmpTarget) -> Result<snmp2::SyncSession, PollError> {
    match &target.version {
        SnmpVersion::V2c { community } => snmp2::SyncSession::new_v2c(
            target.addr.as_str(),
            community.as_bytes(),
            Some(Duration::from_secs(2)),
            0,
        )
        .map_err(|err| PollError::new(err.to_string())),
        SnmpVersion::V3 {
            user,
            auth,
            privacy,
        } => {
            let security = v3_security(user, auth, privacy)?;
            let mut session = snmp2::SyncSession::new_v3(
                target.addr.as_str(),
                Some(Duration::from_secs(2)),
                0,
                security,
            )
            .map_err(|err| PollError::new(err.to_string()))?;
            // Discover authoritative engine ID/boots/time and localize keys
            // before the first authenticated, encrypted PDU.
            session
                .init()
                .map_err(|err| PollError::new(err.to_string()))?;
            Ok(session)
        }
    }
}

pub fn v3_security(
    user: &str,
    auth_password: &str,
    privacy_password: &str,
) -> Result<snmp2::v3::Security, PollError> {
    if user.is_empty() || auth_password.is_empty() || privacy_password.is_empty() {
        return Err(PollError::new("snmp v3 requires a user and passphrases"));
    }
    Ok(
        snmp2::v3::Security::new(user.as_bytes(), auth_password.as_bytes())
            .with_auth_protocol(snmp2::v3::AuthProtocol::Sha256)
            .with_auth(snmp2::v3::Auth::AuthPriv {
                cipher: snmp2::v3::Cipher::Aes128,
                privacy_password: privacy_password.as_bytes().to_vec(),
            }),
    )
}

pub fn snmp_v3_security(
    user: &str,
    auth_password: &str,
    privacy_password: &str,
) -> Result<(), PollError> {
    v3_security(user, auth_password, privacy_password).map(|_| ())
}

#[allow(dead_code)]
fn parse_oid(text: &str) -> Result<snmp2::Oid<'static>, PollError> {
    let parts = text
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u64>()
                .map_err(|_| PollError::new("oid is not numeric"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    snmp2::Oid::from(parts.as_slice()).map_err(|err| PollError::new(format!("oid: {err:?}")))
}

pub fn snmp_templates() -> Vec<TemplateDoc> {
    [
        include_str!("../../templates/snmp-generic.yaml"),
        include_str!("../../templates/snmp-if-mib.yaml"),
        include_str!("../../templates/snmp-ups-mib.yaml"),
    ]
    .into_iter()
    .map(|text| template_from_yaml(text).expect("snmp template"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePoller;

    #[async_trait]
    impl SnmpPoller for FakePoller {
        async fn get(&self, _target: &SnmpTarget, oid: &str) -> Result<SnmpVar, PollError> {
            Ok(SnmpVar {
                oid: oid.to_string(),
                value: "1".to_string(),
            })
        }

        async fn walk(&self, _target: &SnmpTarget, oid: &str) -> Result<Vec<SnmpVar>, PollError> {
            Ok(vec![SnmpVar {
                oid: format!("{oid}.1"),
                value: "eth0".to_string(),
            }])
        }
    }

    #[test]
    fn snmp_v3_selects_sha256_and_aes() {
        let security = v3_security("monitor", "auth-secret", "priv-secret").unwrap();
        assert_eq!(security.username(), b"monitor");
        assert!(snmp_v3_security("", "a", "b").is_err());
        assert_eq!(IF_TABLE, "1.3.6.1.2.1.2.2.1");
        assert_eq!(IF_X_TABLE, "1.3.6.1.2.1.31.1.1.1");
        let names: Vec<_> = snmp_templates().into_iter().map(|doc| doc.name).collect();
        assert!(names.iter().any(|name| name.contains("IF-MIB")));
        assert!(names.iter().any(|name| name.contains("UPS-MIB")));
    }

    #[test]
    fn snmp_decodes_numeric_values_and_redacts_credentials() {
        assert_eq!(
            value_text(snmp2::Value::Counter64(4294967300)).as_deref(),
            Some("4294967300")
        );
        assert_eq!(
            value_text(snmp2::Value::OctetString(b"uplink")).as_deref(),
            Some("uplink")
        );
        assert!(value_text(snmp2::Value::EndOfMibView).is_none());
        let version = SnmpVersion::V3 {
            user: "fixture-user".into(),
            auth: "fixture-auth".into(),
            privacy: "fixture-privacy".into(),
        };
        let debug = format!("{version:?}");
        assert!(!debug.contains("fixture"));
    }

    #[tokio::test]
    async fn snmp_timeout_releases_the_permit() {
        let pool = TimeoutPool::new(1);
        let hold = pool.permits.clone().acquire_owned().await.unwrap();
        let pool_timeout = TimeoutPool {
            permits: Arc::clone(&pool.permits),
        };
        let err = pool_timeout
            .run(Duration::from_millis(30), std::future::pending::<()>())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"));
        drop(hold);
        let ok = pool
            .run(Duration::from_millis(200), async { 7 })
            .await
            .unwrap();
        assert_eq!(ok, 7);
        let poller = FakePoller;
        let target = SnmpTarget {
            addr: "127.0.0.1:1161".to_string(),
            version: SnmpVersion::V2c {
                community: "public".to_string(),
            },
        };
        let var = poller.get(&target, IF_TABLE).await.unwrap();
        assert_eq!(var.value, "1");
    }

    #[tokio::test]
    #[ignore = "requires the snmpsim compose profile"]
    async fn snmp_walks_snmpsim() {
        let poller = BlockingPoller;
        let target = SnmpTarget {
            addr: std::env::var("SNMPSIM_ADDR").unwrap_or_else(|_| "127.0.0.1:1161".into()),
            version: SnmpVersion::V2c {
                community: "public".to_string(),
            },
        };
        let value = poller.get(&target, "1.3.6.1.2.1.1.3.0").await.unwrap();
        assert!(value.value.parse::<u64>().unwrap() > 0);
        let rows = poller.walk(&target, IF_X_TABLE).await.unwrap();
        assert!(rows.iter().any(|row| row.value == "uplink"));
        assert!(rows.iter().any(|row| row.value == "4294967300"));
    }

    #[tokio::test]
    #[ignore = "requires an isolated simulator and SNMPSIM_AUTH_FILE; use scripts/test-snmp.sh"]
    async fn snmp_v3_authpriv_snmpsim() {
        let path = std::env::var("SNMPSIM_AUTH_FILE")
            .expect("SNMPSIM_AUTH_FILE must point to the protected fixture credentials");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let field = |name: &str| {
            fixture[name]
                .as_str()
                .expect("invalid simulator fixture")
                .to_string()
        };
        let target = SnmpTarget {
            addr: field("addr"),
            version: SnmpVersion::V3 {
                user: field("user"),
                auth: field("auth"),
                privacy: field("privacy"),
            },
        };
        let value = BlockingPoller
            .get(&target, "1.3.6.1.2.1.1.3.0")
            .await
            .unwrap();
        assert_eq!(value.value, "12345");
        let rows = BlockingPoller.walk(&target, IF_X_TABLE).await.unwrap();
        assert!(rows.iter().any(|row| row.value == "4294967300"));
    }
}
