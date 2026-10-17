//! One-time enrolment and certificate renewal.
//!
//! Enrollment verifies the server using public roots or an out-of-band CA
//! before presenting the token. The returned CA pins later connections. Renewal runs once
//! two thirds of the certificate lifetime has elapsed.

use crate::config::AgentConfigFile;
use crate::perms;
use crate::shipper::{self, ClientIdentity};
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use x509_parser::prelude::*;

const AGENT_SAN_PREFIX: &str = "kestrel://agent/";

/// Material the shipper needs after enrolment.
#[derive(Clone)]
pub struct Identity {
    pub agent_id: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
}

impl Identity {
    pub fn client_identity(&self) -> ClientIdentity {
        ClientIdentity {
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
            ca_pem: self.ca_pem.clone(),
        }
    }
}

/// Enrol when a token is configured and no certificate exists yet.
///
/// An existing certificate is renewed when [`needs_renew`] is true.
pub async fn ensure(cfg: &AgentConfigFile) -> Result<Option<Identity>, IdentityError> {
    crate::config::validate_server_url(&cfg.server_url)
        .map_err(|err| IdentityError::new(err.to_string()))?;
    if let Some(existing) = load(&cfg.data_dir)? {
        return Ok(Some(
            renew_if_due(&cfg.server_url, &cfg.data_dir, existing).await?,
        ));
    }
    if cfg.enrol_token.is_some() {
        return Ok(Some(enrol_new(cfg).await?));
    }
    Ok(None)
}

/// Renew when due. `Ok(None)` means the current certificate is still in its
/// first two thirds, or the agent has not enrolled.
pub async fn refresh(data_dir: &Path, server_url: &Url) -> Result<Option<Identity>, IdentityError> {
    let Some(existing) = load(data_dir)? else {
        return Ok(None);
    };
    let before = existing.cert_pem.clone();
    let updated = renew_if_due(server_url, data_dir, existing).await?;
    if updated.cert_pem == before {
        Ok(None)
    } else {
        Ok(Some(updated))
    }
}

/// True when `now` is at least two thirds of the way from `not_before` to `not_after`.
pub fn needs_renew(not_before: i64, not_after: i64, now: i64) -> bool {
    let life = not_after.saturating_sub(not_before);
    if life <= 0 {
        return true;
    }
    let elapsed = now.saturating_sub(not_before);
    if elapsed < 0 {
        return false;
    }
    elapsed.saturating_mul(3) >= life.saturating_mul(2)
}

#[derive(Debug)]
pub struct IdentityError {
    message: String,
}

impl IdentityError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}

impl From<shipper::ShipError> for IdentityError {
    fn from(err: shipper::ShipError) -> Self {
        Self::new(err.to_string())
    }
}

#[derive(Serialize)]
struct EnrolRequest<'a> {
    token: &'a str,
    csr_pem: String,
    hostname: String,
    os: &'static str,
    arch: &'static str,
}

#[derive(Deserialize)]
struct EnrolResponse {
    agent_id: Uuid,
    cert_pem: String,
    ca_pem: String,
}

#[derive(Serialize)]
struct RenewRequest {
    csr_pem: String,
}

#[derive(Deserialize)]
struct RenewResponse {
    cert_pem: String,
    ca_pem: String,
}

async fn enrol_new(cfg: &AgentConfigFile) -> Result<Identity, IdentityError> {
    let token = cfg
        .enrol_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| IdentityError::new("enrol token is missing"))?;
    if cfg.server_url.scheme() != "https" {
        return Err(IdentityError::new("enrolment requires an https server_url"));
    }
    let (key_pem, csr_pem) = new_csr()?;
    tracing::info!(server = %cfg.server_url, "enrolling agent");
    let client = bootstrap_client(cfg.bootstrap_ca_path.as_deref())?;
    let url = service_url(&cfg.server_url, "api/v1/enrol")?;
    let response = client
        .post(url)
        .json(&EnrolRequest {
            token,
            csr_pem,
            hostname: local_hostname(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        })
        .send()
        .await
        .map_err(|err| IdentityError::new(err.to_string()))?;
    if !response.status().is_success() {
        return Err(IdentityError::new(format!(
            "enrolment failed with status {}",
            response.status()
        )));
    }
    let body: EnrolResponse = response
        .json()
        .await
        .map_err(|err| IdentityError::new(err.to_string()))?;
    let identity = Identity {
        agent_id: body.agent_id.to_string(),
        cert_pem: body.cert_pem,
        key_pem,
        ca_pem: body.ca_pem,
    };
    save(&cfg.data_dir, &identity)?;
    tracing::info!(agent_id = %identity.agent_id, "agent enrolled");
    Ok(identity)
}

async fn renew_if_due(
    server_url: &Url,
    data_dir: &Path,
    current: Identity,
) -> Result<Identity, IdentityError> {
    let (not_before, not_after) = validity_unix(&current.cert_pem)?;
    let now = unix_now();
    if !needs_renew(not_before, not_after, now) {
        return Ok(current);
    }
    match renew(server_url, data_dir, current.clone()).await {
        Ok(updated) => Ok(updated),
        Err(err) if now < not_after => {
            tracing::warn!(error = %err, "certificate renewal failed");
            Ok(current)
        }
        Err(err) => Err(err),
    }
}

async fn renew(
    server_url: &Url,
    data_dir: &Path,
    current: Identity,
) -> Result<Identity, IdentityError> {
    let (key_pem, csr_pem) = new_csr()?;
    let client = shipper::mtls_client(&current.client_identity())?;
    let url = service_url(server_url, "api/v1/renew")?;
    let response = client
        .post(url)
        .json(&RenewRequest { csr_pem })
        .send()
        .await
        .map_err(|err| IdentityError::new(err.to_string()))?;
    if !response.status().is_success() {
        return Err(IdentityError::new(format!(
            "renewal failed with status {}",
            response.status()
        )));
    }
    let body: RenewResponse = response
        .json()
        .await
        .map_err(|err| IdentityError::new(err.to_string()))?;
    let identity = Identity {
        agent_id: current.agent_id,
        cert_pem: body.cert_pem,
        key_pem,
        ca_pem: body.ca_pem,
    };
    save(data_dir, &identity)?;
    tracing::info!(agent_id = %identity.agent_id, "agent certificate renewed");
    Ok(identity)
}

fn new_csr() -> Result<(String, String), IdentityError> {
    let key = KeyPair::generate().map_err(|err| IdentityError::new(err.to_string()))?;
    let params = CertificateParams::new(vec!["kestrel-agent".to_string()])
        .map_err(|err| IdentityError::new(err.to_string()))?;
    let csr = params
        .serialize_request(&key)
        .map_err(|err| IdentityError::new(err.to_string()))?;
    let csr_pem = csr
        .pem()
        .map_err(|err| IdentityError::new(err.to_string()))?;
    Ok((key.serialize_pem(), csr_pem))
}

fn load(data_dir: &Path) -> Result<Option<Identity>, IdentityError> {
    let paths = paths(data_dir);
    let present = [
        paths.key.is_file(),
        paths.cert.is_file(),
        paths.ca.is_file(),
    ];
    if present == [false, false, false] {
        return Ok(None);
    }
    if present != [true, true, true] {
        return Err(IdentityError::new("agent certificate files are incomplete"));
    }
    let identity = Identity {
        key_pem: std::fs::read_to_string(&paths.key)?,
        cert_pem: std::fs::read_to_string(&paths.cert)?,
        ca_pem: std::fs::read_to_string(&paths.ca)?,
        agent_id: String::new(),
    };
    let agent_id = agent_id_from_pem(&identity.cert_pem)?;
    Ok(Some(Identity {
        agent_id,
        ..identity
    }))
}

struct IdentityPaths {
    key: PathBuf,
    cert: PathBuf,
    ca: PathBuf,
}

fn paths(data_dir: &Path) -> IdentityPaths {
    IdentityPaths {
        key: data_dir.join("agent.key"),
        cert: data_dir.join("agent.crt"),
        ca: data_dir.join("ca.crt"),
    }
}

fn save(data_dir: &Path, identity: &Identity) -> Result<(), IdentityError> {
    let paths = paths(data_dir);
    perms::write_private_key(&paths.key, &identity.key_pem)?;
    perms::write_certificate(&paths.cert, &identity.cert_pem)?;
    perms::write_certificate(&paths.ca, &identity.ca_pem)?;
    let tmp = data_dir.join("agent_id.tmp");
    std::fs::write(&tmp, &identity.agent_id)?;
    replace_file(&tmp, &data_dir.join("agent_id"))?;
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

fn bootstrap_client(ca_path: Option<&Path>) -> Result<reqwest::Client, IdentityError> {
    // Authenticate the server before sending a bearer enrollment token.
    // Private PKI trust must be distributed out of band, never learned from
    // an unauthenticated enrollment response.
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = ca_path {
        let pem = std::fs::read(path)?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| IdentityError::new("invalid bootstrap CA PEM"))?;
        if certificates.is_empty() {
            return Err(IdentityError::new(
                "bootstrap CA file contains no certificates",
            ));
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder
        .build()
        .map_err(|err| IdentityError::new(err.to_string()))
}

fn service_url(server: &Url, path: &str) -> Result<Url, IdentityError> {
    crate::config::validate_server_url(server)
        .map_err(|err| IdentityError::new(err.to_string()))?;
    let mut base = server.clone();
    if !base.path().ends_with('/') {
        let joined = format!("{}/", base.path());
        base.set_path(&joined);
    }
    base.join(path)
        .map_err(|err| IdentityError::new(err.to_string()))
}

fn local_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn validity_unix(cert_pem: &str) -> Result<(i64, i64), IdentityError> {
    let der = first_cert_der(cert_pem)?;
    let (_, cert) = parse_x509_certificate(&der)
        .map_err(|err| IdentityError::new(format!("certificate: {err}")))?;
    Ok((
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    ))
}

fn agent_id_from_pem(cert_pem: &str) -> Result<String, IdentityError> {
    let der = first_cert_der(cert_pem)?;
    let (_, cert) = parse_x509_certificate(&der)
        .map_err(|err| IdentityError::new(format!("certificate: {err}")))?;
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(|err| IdentityError::new(format!("certificate san: {err}")))?
    else {
        return Err(IdentityError::new(
            "certificate has no subject alternative name",
        ));
    };
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            if let Some(id) = uri.strip_prefix(AGENT_SAN_PREFIX) {
                Uuid::parse_str(id).map_err(|err| IdentityError::new(err.to_string()))?;
                return Ok(id.to_string());
            }
        }
    }
    Err(IdentityError::new("certificate has no kestrel agent name"))
}

fn first_cert_der(pem: &str) -> Result<Vec<u8>, IdentityError> {
    let mut reader = pem.as_bytes();
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| IdentityError::new("certificate pem is empty"))?
        .map_err(|err| IdentityError::new(err.to_string()))?;
    Ok(cert.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_starts_at_two_thirds_of_the_lifetime() {
        let day = 24 * 60 * 60;
        assert!(!needs_renew(0, 90 * day, 60 * day - 1));
        assert!(needs_renew(0, 90 * day, 60 * day));
        assert!(needs_renew(0, 90 * day, 89 * day));
        assert!(!needs_renew(1_000, 1_000 + 90 * day, 1_000));
    }

    #[test]
    fn private_key_permissions_exclude_other_users() {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-agent-key-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.key");
        perms::write_private_key(&path, "not-a-real-key\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "mode {mode:o}");
        }
        #[cfg(windows)]
        {
            let output = std::process::Command::new("icacls")
                .arg(&path)
                .output()
                .unwrap();
            let text = crate::perms::output_text(&output.stdout);
            let folded = text.to_ascii_lowercase();
            assert!(output.status.success(), "{text}");
            assert!(folded.contains("system"), "{text}");
            assert!(folded.contains("administrators"), "{text}");
            assert!(!folded.contains("everyone"), "{text}");
            assert!(!folded.contains("builtin\\users"), "{text}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
