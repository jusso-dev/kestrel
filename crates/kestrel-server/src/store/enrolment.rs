//! File-backed enrolment records.
//!
//! Token hashes and agent certificates live under the server data directory
//! until the PostgreSQL schema owns the same fields.

use crate::ServerError;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Tenant used until the database schema seeds its own default row.
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

const TOKEN_REJECTED: &str = "enrolment token rejected";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrolToken {
    id: Uuid,
    tenant_id: Uuid,
    token_hash: String,
    host_group_id: Option<String>,
    expires_at: String,
    used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentRecord {
    id: Uuid,
    tenant_id: Uuid,
    hostname: String,
    os: String,
    arch: String,
    cert_serial: String,
    cert_not_after: String,
    revoked_at: Option<String>,
    #[serde(default)]
    host_group_id: Option<String>,
}

#[derive(Clone)]
pub struct EnrolledAgent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cert_serial: String,
    pub cert_not_after: String,
    pub host_group_id: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct FileState {
    tokens: Vec<EnrolToken>,
    agents: Vec<AgentRecord>,
    #[serde(default)]
    security_events: Vec<AgentSecurityEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentSecurityEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub hostname: String,
    pub kind: String,
    pub observed_at: String,
}

fn security_event(
    state: &mut FileState,
    agent: &AgentRecord,
    kind: &str,
) -> Result<(), ServerError> {
    state.security_events.push(AgentSecurityEvent {
        id: Uuid::new_v4(),
        tenant_id: agent.tenant_id,
        agent_id: agent.id,
        hostname: agent.hostname.clone(),
        kind: kind.to_string(),
        observed_at: format_time(OffsetDateTime::now_utc())?,
    });
    Ok(())
}

pub struct EnrolCommit {
    pub token: String,
    pub agent_id: Uuid,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cert_serial: String,
    pub cert_not_after: String,
}

/// `enrolment.json` in the server data directory.
///
/// Each call reloads the file so a token created by another process is visible.
pub struct Directory {
    path: PathBuf,
    gate: Mutex<()>,
}

impl Directory {
    pub fn open(dir: &Path) -> Result<Self, ServerError> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.join("enrolment.json"),
            gate: Mutex::new(()),
        })
    }

    /// Return a new token once. Only its SHA-256 hash is stored.
    pub fn create_token(
        &self,
        group: Option<String>,
        ttl: Duration,
    ) -> Result<String, ServerError> {
        self.create_token_for(DEFAULT_TENANT_ID, group, ttl)
    }

    pub fn create_token_for(
        &self,
        tenant_id: Uuid,
        group: Option<String>,
        ttl: Duration,
    ) -> Result<String, ServerError> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|err| ServerError::new(err.to_string()))?;
        let token = data_encoding::BASE32_NOPAD.encode(&raw);
        let now = OffsetDateTime::now_utc();
        let expires = if ttl.is_zero() {
            now - time::Duration::seconds(1)
        } else {
            let ttl =
                time::Duration::try_from(ttl).map_err(|_| ServerError::new("ttl is too large"))?;
            now + ttl
        };
        let record = EnrolToken {
            id: Uuid::new_v4(),
            tenant_id,
            token_hash: HEXLOWER.encode(&hash_token(&token)),
            host_group_id: group,
            expires_at: format_time(expires)?,
            used_at: None,
        };
        self.with_mut(|state| {
            state.tokens.push(record);
            Ok(())
        })?;
        Ok(token)
    }

    pub fn check_token(&self, token: &str) -> Result<(), ServerError> {
        self.with_ref(|state| {
            let index = find_token(&state.tokens, token).ok_or_else(token_rejected)?;
            validate_token(&state.tokens[index])
        })
    }

    pub fn commit_enrol(&self, commit: EnrolCommit) -> Result<(), ServerError> {
        self.with_mut(|state| {
            let index = find_token(&state.tokens, &commit.token).ok_or_else(token_rejected)?;
            validate_token(&state.tokens[index])?;
            state.tokens[index].used_at = Some(format_time(OffsetDateTime::now_utc())?);
            state.agents.push(AgentRecord {
                id: commit.agent_id,
                tenant_id: state.tokens[index].tenant_id,
                host_group_id: state.tokens[index].host_group_id.clone(),
                hostname: commit.hostname,
                os: commit.os,
                arch: commit.arch,
                cert_serial: commit.cert_serial,
                cert_not_after: commit.cert_not_after,
                revoked_at: None,
            });
            let agent = state
                .agents
                .last()
                .cloned()
                .ok_or_else(|| ServerError::new("agent missing after enrolment"))?;
            security_event(state, &agent, "agent.enrolled")?;
            Ok(())
        })
    }

    pub fn commit_renew(
        &self,
        agent_id: Uuid,
        cert_serial: &str,
        cert_not_after: &str,
    ) -> Result<(), ServerError> {
        self.with_mut(|state| {
            let Some(agent) = state.agents.iter_mut().find(|agent| agent.id == agent_id) else {
                return Err(token_rejected());
            };
            if agent.revoked_at.is_some() {
                return Err(token_rejected());
            }
            agent.cert_serial = cert_serial.to_string();
            agent.cert_not_after = cert_not_after.to_string();
            let agent = agent.clone();
            security_event(state, &agent, "agent.certificate_renewed")?;
            Ok(())
        })
    }

    pub fn authorize(&self, agent_id: Uuid, serial_hex: &str) -> bool {
        self.with_ref(|state| {
            Ok(state.agents.iter().any(|agent| {
                agent.id == agent_id
                    && agent.revoked_at.is_none()
                    && agent.cert_serial == serial_hex
            }))
        })
        .unwrap_or(false)
    }

    pub fn agent_meta(&self, agent_id: Uuid) -> Option<(Uuid, String)> {
        self.with_ref(|state| {
            Ok(state.agents.iter().find_map(|agent| {
                if agent.id == agent_id && agent.revoked_at.is_none() {
                    Some((agent.tenant_id, agent.hostname.clone()))
                } else {
                    None
                }
            }))
        })
        .ok()
        .flatten()
    }

    pub fn agent_details(&self, agent_id: Uuid) -> Option<EnrolledAgent> {
        self.with_ref(|state| {
            Ok(state
                .agents
                .iter()
                .find(|agent| agent.id == agent_id && agent.revoked_at.is_none())
                .map(|agent| EnrolledAgent {
                    id: agent.id,
                    tenant_id: agent.tenant_id,
                    hostname: agent.hostname.clone(),
                    os: agent.os.clone(),
                    arch: agent.arch.clone(),
                    cert_serial: agent.cert_serial.clone(),
                    cert_not_after: agent.cert_not_after.clone(),
                    host_group_id: agent.host_group_id.clone(),
                }))
        })
        .ok()
        .flatten()
    }

    pub fn revoke(&self, agent_id: Uuid) -> Result<(), ServerError> {
        self.with_mut(|state| {
            let Some(agent) = state.agents.iter_mut().find(|agent| agent.id == agent_id) else {
                return Err(ServerError::new("agent not found"));
            };
            if agent.revoked_at.is_none() {
                agent.revoked_at = Some(format_time(OffsetDateTime::now_utc())?);
                let agent = agent.clone();
                security_event(state, &agent, "agent.revoked")?;
            }
            Ok(())
        })
    }

    pub(crate) fn security_meta(&self, id: Uuid) -> Option<Uuid> {
        self.with_ref(|state| {
            Ok(state
                .agents
                .iter()
                .find(|agent| agent.id == id)
                .map(|agent| agent.tenant_id))
        })
        .ok()
        .flatten()
    }
    pub(crate) fn record_security_rejection(&self, id: Uuid) -> Result<(), ServerError> {
        self.with_mut(|state| {
            let Some(agent) = state.agents.iter().find(|agent| agent.id == id).cloned() else {
                return Ok(());
            };
            security_event(state, &agent, "agent.authentication_rejected")
        })
    }
    pub(crate) fn pending_security_events(&self) -> Result<Vec<AgentSecurityEvent>, ServerError> {
        self.with_ref(|state| Ok(state.security_events.iter().take(100).cloned().collect()))
    }
    pub(crate) fn ack_security_event(&self, id: Uuid) -> Result<(), ServerError> {
        self.with_mut(|state| {
            state.security_events.retain(|event| event.id != id);
            Ok(())
        })
    }

    fn with_ref<T>(
        &self,
        f: impl FnOnce(&FileState) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        let _gate = self.gate.lock().unwrap_or_else(|err| err.into_inner());
        let _file = FileLock::acquire(&self.lock_path())?;
        let state = load_state(&self.path)?;
        f(&state)
    }

    fn with_mut<T>(
        &self,
        f: impl FnOnce(&mut FileState) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        let _gate = self.gate.lock().unwrap_or_else(|err| err.into_inner());
        let _file = FileLock::acquire(&self.lock_path())?;
        let mut state = load_state(&self.path)?;
        let value = f(&mut state)?;
        save_state(&self.path, &state)?;
        Ok(value)
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }
}

struct FileLock {
    path: PathBuf,
}

impl FileLock {
    fn acquire(path: &Path) -> Result<Self, ServerError> {
        for _ in 0..100 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                    })
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(path) {
                        let _ = std::fs::remove_file(path);
                    } else {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
        Err(ServerError::new("enrolment store is locked"))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .map(|age| age > Duration::from_secs(30))
        .unwrap_or(false)
}

fn load_state(path: &Path) -> Result<FileState, ServerError> {
    if !path.is_file() {
        return Ok(FileState::default());
    }
    let text = std::fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(FileState::default());
    }
    serde_json::from_str(&text).map_err(|err| ServerError::new(format!("enrolment store: {err}")))
}

fn save_state(path: &Path, state: &FileState) -> Result<(), ServerError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|err| ServerError::new(format!("enrolment store: {err}")))?;
    atomic_write(path, &bytes)
}

fn token_rejected() -> ServerError {
    ServerError::new(TOKEN_REJECTED)
}

fn validate_token(token: &EnrolToken) -> Result<(), ServerError> {
    if token.used_at.is_some() {
        return Err(token_rejected());
    }
    let expires = OffsetDateTime::parse(&token.expires_at, &Rfc3339)
        .map_err(|err| ServerError::new(format!("enrolment store: {err}")))?;
    if OffsetDateTime::now_utc() >= expires {
        return Err(token_rejected());
    }
    Ok(())
}

fn find_token(tokens: &[EnrolToken], presented: &str) -> Option<usize> {
    let digest = hash_token(presented);
    let mut found = None;
    for (index, token) in tokens.iter().enumerate() {
        let Ok(stored) = HEXLOWER.decode(token.token_hash.as_bytes()) else {
            continue;
        };
        if ct_eq(&digest, &stored) {
            found = Some(index);
        }
    }
    found
}

fn hash_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn format_time(value: OffsetDateTime) -> Result<String, ServerError> {
    value
        .format(&Rfc3339)
        .map_err(|err| ServerError::new(err.to_string()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ServerError> {
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    replace_file(&tmp, path)?;
    Ok(())
}

fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(err) => {
            if to.exists() {
                std::fs::remove_file(to)?;
                std::fs::rename(from, to)
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kestrel-store-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn token_file_stores_the_hash_only() {
        let dir = scratch("hash");
        let store = Directory::open(&dir).unwrap();
        let token = store
            .create_token(Some("linux".to_string()), Duration::from_secs(3600))
            .unwrap();
        let text = std::fs::read_to_string(dir.join("enrolment.json")).unwrap();
        assert!(!text.contains(&token));
        assert!(text.contains("linux"));
        store.check_token(&token).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_token_is_rejected() {
        let dir = scratch("expired");
        let store = Directory::open(&dir).unwrap();
        let token = store.create_token(None, Duration::ZERO).unwrap();
        let err = store.check_token(&token).unwrap_err();
        assert_eq!(err.to_string(), TOKEN_REJECTED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
