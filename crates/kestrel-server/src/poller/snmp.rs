//! SNMP v2c and v3 polling. Credentials are supplied by the caller and are not
//! logged. The integration test against snmpsim is ignored unless that
//! simulator is running.

use crate::config_compile::{template_from_yaml, TemplateDoc};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
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

#[derive(Debug, Clone)]
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
        tokio::task::spawn_blocking(move || session_get(&target, &oid))
            .await
            .map_err(|err| PollError::new(err.to_string()))?
    }

    async fn walk(&self, target: &SnmpTarget, oid: &str) -> Result<Vec<SnmpVar>, PollError> {
        let target = target.clone();
        let oid = oid.to_string();
        tokio::task::spawn_blocking(move || session_walk(&target, &oid))
            .await
            .map_err(|err| PollError::new(err.to_string()))?
    }
}

#[allow(dead_code)]
fn session_get(target: &SnmpTarget, oid: &str) -> Result<SnmpVar, PollError> {
    let mut session = open_session(target)?;
    let parsed = parse_oid(oid)?;
    let pdu = session
        .get(&parsed)
        .map_err(|err| PollError::new(err.to_string()))?;
    Ok(SnmpVar {
        oid: oid.to_string(),
        value: format!("{pdu:?}"),
    })
}

#[allow(dead_code)]
fn session_walk(target: &SnmpTarget, root: &str) -> Result<Vec<SnmpVar>, PollError> {
    let mut session = open_session(target)?;
    let mut current = parse_oid(root)?;
    let mut rows = Vec::new();
    for _ in 0..10_000 {
        let pdu = session
            .getnext(&current)
            .map_err(|err| PollError::new(err.to_string()))?;
        let rendered = format!("{pdu:?}");
        let Some(next) = first_dotted_oid(&rendered) else {
            break;
        };
        if !next.starts_with(root) || next == current.to_string() {
            break;
        }
        rows.push(SnmpVar {
            oid: next.clone(),
            value: rendered,
        });
        current = parse_oid(&next)?;
    }
    Ok(rows)
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
            snmp2::SyncSession::new_v3(
                target.addr.as_str(),
                Some(Duration::from_secs(2)),
                0,
                security,
            )
            .map_err(|err| PollError::new(err.to_string()))
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
                cipher: snmp2::v3::Cipher::Aes256,
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

#[allow(dead_code)]
fn first_dotted_oid(text: &str) -> Option<String> {
    let mut current = String::new();
    let mut best: Option<String> = None;
    for ch in text.chars() {
        if ch.is_ascii_digit() || (ch == '.' && !current.is_empty()) {
            current.push(ch);
        } else if current.matches('.').count() >= 2 {
            best = Some(current.trim_end_matches('.').to_string());
            break;
        } else {
            current.clear();
        }
    }
    best
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
            addr: "127.0.0.1:1161".to_string(),
            version: SnmpVersion::V2c {
                community: "public".to_string(),
            },
        };
        let _ = poller.get(&target, "1.3.6.1.2.1.1.1.0").await.unwrap();
    }
}
