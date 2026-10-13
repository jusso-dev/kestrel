//! Internal ECDSA P-256 certificate authority.
//!
//! rcgen 0.13 can parse a CA into [`rcgen::CertificateParams`] but not into a
//! [`rcgen::Certificate`]. After the PEM files are written, the issuer used for
//! later signatures is rebuilt with the parsed parameters and the same key.
//! Agents still receive the original CA PEM.

use crate::perms;
use crate::ServerError;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use std::path::Path;
use uuid::Uuid;
use x509_parser::prelude::*;

const CA_YEARS_DAYS: i64 = 365 * 10;
const AGENT_DAYS: i64 = 90;
const SERVER_DAYS: i64 = 397;
pub(crate) const AGENT_SAN_PREFIX: &str = "kestrel://agent/";

/// CA certificate PEM plus the key that signs agent certificates.
pub struct Ca {
    cert_pem: String,
    certificate: Certificate,
    key: KeyPair,
}

pub struct IssuedCert {
    pub pem: String,
    pub serial_hex: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub not_after_rfc3339: String,
}

pub struct ServerMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug)]
pub struct PresentedIdentity {
    pub agent_id: Uuid,
    pub serial_hex: String,
}

impl Ca {
    /// Create a 10-year CA when the files are absent, then load whatever is on disk.
    pub fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<Self, ServerError> {
        if cert_path.is_file() && key_path.is_file() {
            perms::restrict_private_key(key_path)?;
            return Self::load(cert_path, key_path);
        }
        if cert_path.exists() || key_path.exists() {
            return Err(ServerError::new(
                "CA certificate and key must both exist or both be absent",
            ));
        }
        let (cert_pem, key_pem) = generate_ca()?;
        perms::write_certificate(cert_path, &cert_pem)?;
        perms::write_private_key(key_path, &key_pem)?;
        Self::load(cert_path, key_path)
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Sign a 90-day client certificate whose SAN is `kestrel://agent/<id>`.
    pub fn sign_agent(&self, csr_pem: &str, agent_id: Uuid) -> Result<IssuedCert, ServerError> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|err| ServerError::new(format!("could not read the csr: {err}")))?;
        let now = ::time::OffsetDateTime::now_utc();
        let uri = format!("{AGENT_SAN_PREFIX}{agent_id}");
        let uri = rcgen::Ia5String::try_from(uri)
            .map_err(|err| ServerError::new(format!("agent uri: {err}")))?;
        csr.params.subject_alt_names = vec![SanType::URI(uri)];
        csr.params.not_before = now;
        csr.params.not_after = now + ::time::Duration::days(AGENT_DAYS);
        csr.params.is_ca = IsCa::NoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.use_authority_key_identifier_extension = true;
        let cert = csr.signed_by(&self.certificate, &self.key).map_err(|err| {
            ServerError::new(format!("could not sign the agent certificate: {err}"))
        })?;
        issued_from_pem(cert.pem())
    }

    pub fn issue_server(
        &self,
        dns_names: &[String],
        ips: &[IpAddr],
    ) -> Result<ServerMaterial, ServerError> {
        let names = if dns_names.is_empty() {
            vec!["localhost".to_string()]
        } else {
            dns_names.to_vec()
        };
        let mut params = CertificateParams::new(names)
            .map_err(|err| ServerError::new(format!("server certificate names: {err}")))?;
        for ip in ips {
            params.subject_alt_names.push(SanType::IpAddress(*ip));
        }
        params
            .distinguished_name
            .push(DnType::CommonName, "Kestrel Server");
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + ::time::Duration::days(SERVER_DAYS);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key =
            KeyPair::generate().map_err(|err| ServerError::new(format!("server key: {err}")))?;
        let cert = params
            .signed_by(&key, &self.certificate, &self.key)
            .map_err(|err| ServerError::new(format!("server certificate: {err}")))?;
        Ok(ServerMaterial {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, ServerError> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|err| ServerError::new(format!("could not read the CA key: {err}")))?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .map_err(|err| ServerError::new(format!("could not read the CA certificate: {err}")))?;
        let certificate = params.self_signed(&key).map_err(|err| {
            ServerError::new(format!(
                "could not use the CA certificate for signing: {err}"
            ))
        })?;
        Ok(Self {
            cert_pem,
            certificate,
            key,
        })
    }
}

fn generate_ca() -> Result<(String, String), ServerError> {
    let key = KeyPair::generate().map_err(|err| ServerError::new(format!("CA key: {err}")))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|err| ServerError::new(format!("CA certificate: {err}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Kestrel Internal CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Kestrel");
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + ::time::Duration::days(CA_YEARS_DAYS);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params
        .self_signed(&key)
        .map_err(|err| ServerError::new(format!("CA certificate: {err}")))?;
    Ok((cert.pem(), key.serialize_pem()))
}

pub fn presented_identity(der: &[u8]) -> Result<PresentedIdentity, ServerError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|err| ServerError::new(format!("client certificate: {err}")))?;
    let agent_id = agent_id_of(&cert)?;
    Ok(PresentedIdentity {
        agent_id,
        serial_hex: serial_hex(&cert),
    })
}

fn issued_from_pem(pem: String) -> Result<IssuedCert, ServerError> {
    let der = first_certificate(&pem)?;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|err| ServerError::new(format!("issued certificate: {err}")))?;
    let not_before_unix = cert.validity().not_before.timestamp();
    let not_after_unix = cert.validity().not_after.timestamp();
    let not_after_rfc3339 = ::time::OffsetDateTime::from_unix_timestamp(not_after_unix)
        .map_err(|err| ServerError::new(err.to_string()))?
        .format(&::time::format_description::well_known::Rfc3339)
        .map_err(|err| ServerError::new(err.to_string()))?;
    Ok(IssuedCert {
        pem,
        serial_hex: serial_hex(&cert),
        not_before_unix,
        not_after_unix,
        not_after_rfc3339,
    })
}

fn agent_id_of(cert: &X509Certificate<'_>) -> Result<Uuid, ServerError> {
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(|err| ServerError::new(format!("certificate san: {err}")))?
    else {
        return Err(ServerError::new(
            "certificate has no subject alternative name",
        ));
    };
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            if let Some(id) = uri.strip_prefix(AGENT_SAN_PREFIX) {
                return Uuid::parse_str(id).map_err(|err| ServerError::new(err.to_string()));
            }
        }
    }
    Err(ServerError::new("certificate has no kestrel agent name"))
}

fn serial_hex(cert: &X509Certificate<'_>) -> String {
    cert.raw_serial()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn first_certificate(pem: &str) -> Result<Vec<u8>, ServerError> {
    let mut reader = pem.as_bytes();
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| ServerError::new("certificate pem is empty"))?
        .map_err(|err| ServerError::new(err.to_string()))?;
    Ok(cert.as_ref().to_vec())
}

/// DNS and IP names placed on a generated server certificate.
pub fn server_names(public_url: &url::Url, listen_ip: IpAddr) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns = vec!["localhost".to_string()];
    let mut ips = vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
    if let Some(host) = public_url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        } else if host != "localhost" {
            dns.push(host.to_string());
        }
    }
    if !listen_ip.is_unspecified() && !ips.contains(&listen_ip) {
        ips.push(listen_ip);
    }
    (dns, ips)
}
