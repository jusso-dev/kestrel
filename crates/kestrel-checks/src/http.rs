//! HTTP checks: status, latency, body match, and TLS certificate expiry.
//!
//! Targets come from operator configuration. The checker does not follow
//! redirects and does not send credentials of its own.

use crate::sample;
use kestrel_proto::Sample;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

pub struct HttpCheck {
    pub id: String,
    pub url: String,
    pub timeout: Duration,
    pub body_regex: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpOutcome {
    pub up: bool,
    pub status: Option<u16>,
    pub duration_seconds: f64,
    pub expiry_unix: Option<i64>,
    pub detail: String,
    pub samples: Vec<Sample>,
}

/// `not_after` of a leaf certificate, as unix seconds.
pub fn expiry_from_der(der: &[u8]) -> Option<i64> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    Some(cert.validity().not_after.timestamp())
}

/// Records the leaf certificate's `not_after` and then delegates verification.
pub struct RecordingVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    expiry: Arc<Mutex<Option<i64>>>,
}

impl RecordingVerifier {
    pub fn new(
        inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        expiry: Arc<Mutex<Option<i64>>>,
    ) -> Self {
        Self { inner, expiry }
    }

    pub fn expiry_handle() -> Arc<Mutex<Option<i64>>> {
        Arc::new(Mutex::new(None))
    }
}

impl std::fmt::Debug for RecordingVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordingVerifier")
    }
}

impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(expiry) = expiry_from_der(end_entity.as_ref()) {
            *self.expiry.lock().unwrap_or_else(|err| err.into_inner()) = Some(expiry);
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn ensure_crypto_provider() {
    // reqwest and this crate can both enable a Rustls provider. Install ring
    // explicitly so ClientConfig::builder does not panic when more than one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Connect with the recording verifier and return the leaf `not_after`.
pub async fn probe_tls_expiry(
    host: &str,
    port: u16,
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    expiry: Arc<Mutex<Option<i64>>>,
) -> Option<i64> {
    ensure_crypto_provider();
    let recorder = Arc::new(RecordingVerifier::new(verifier, Arc::clone(&expiry)));
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(recorder)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let addr = format!("{host}:{port}");
    let Ok(stream) = tokio::net::TcpStream::connect(&addr).await else {
        return expiry
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .to_owned();
    };
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let _ = connector.connect(server_name, stream).await;
    expiry
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .to_owned()
}

pub async fn run_http_check(check: &HttpCheck, now_ms: i64) -> HttpOutcome {
    let client = match reqwest::Client::builder()
        .timeout(check.timeout.max(Duration::from_millis(1)))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(err) => return failed(check, now_ms, None, 0.0, &err.to_string()),
    };
    let started = Instant::now();
    let response = client.get(&check.url).send().await;
    let duration = started.elapsed().as_secs_f64();
    match response {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let regex_ok = match &check.body_regex {
                Some(pattern) => regex_matches(pattern, &body),
                None => true,
            };
            let up = (200..400).contains(&status) && regex_ok;
            let detail = if up {
                format!("HTTP {status}")
            } else if !regex_ok {
                format!("HTTP {status} body did not match")
            } else {
                format!("HTTP {status}")
            };
            outcome(check, now_ms, up, Some(status), duration, None, &detail)
        }
        Err(err) => failed(check, now_ms, None, duration, &err.to_string()),
    }
}

fn regex_matches(pattern: &str, body: &str) -> bool {
    if pattern.len() > 200 {
        return false;
    }
    match regex::Regex::new(pattern) {
        Ok(regex) => regex.is_match(body),
        Err(_) => false,
    }
}

fn failed(
    check: &HttpCheck,
    now_ms: i64,
    status: Option<u16>,
    duration: f64,
    detail: &str,
) -> HttpOutcome {
    outcome(check, now_ms, false, status, duration, None, detail)
}

fn outcome(
    check: &HttpCheck,
    now_ms: i64,
    up: bool,
    status: Option<u16>,
    duration: f64,
    expiry: Option<i64>,
    detail: &str,
) -> HttpOutcome {
    let labels = [("target", check.url.as_str()), ("check", check.id.as_str())];
    let mut samples = vec![
        sample(
            "kestrel_http_up",
            &labels,
            if up { 1.0 } else { 0.0 },
            now_ms,
        ),
        sample("kestrel_http_duration_seconds", &labels, duration, now_ms),
    ];
    if let Some(status) = status {
        samples.push(sample(
            "kestrel_http_status_code",
            &labels,
            f64::from(status),
            now_ms,
        ));
    }
    if let Some(expiry) = expiry {
        samples.push(sample(
            "kestrel_tls_cert_expiry_timestamp_seconds",
            &labels,
            expiry as f64,
            now_ms,
        ));
    }
    HttpOutcome {
        up,
        status,
        duration_seconds: duration,
        expiry_unix: expiry,
        detail: detail.chars().take(512).collect(),
        samples,
    }
}

/// Attach a known expiry to an outcome. The TLS probe is separate from the
/// status request so a failed handshake still reports the leaf date.
pub fn with_expiry(
    mut outcome: HttpOutcome,
    check: &HttpCheck,
    expiry: i64,
    now_ms: i64,
) -> HttpOutcome {
    let labels = [("target", check.url.as_str()), ("check", check.id.as_str())];
    outcome.expiry_unix = Some(expiry);
    outcome.samples.push(sample(
        "kestrel_tls_cert_expiry_timestamp_seconds",
        &labels,
        expiry as f64,
        now_ms,
    ));
    let soon = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64 + 7 * 86_400)
        .unwrap_or(i64::MAX);
    if expiry < soon {
        outcome.detail = format!("{}; certificate expires at {expiry}", outcome.detail);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use std::net::SocketAddr;
    use std::sync::Arc;

    #[test]
    fn http_expiry_from_der_reads_not_after() {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let expiry = expiry_from_der(cert.der()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(expiry > now, "not_after {expiry} should be in the future");
    }

    #[tokio::test]
    async fn http_check_detects_status_body_and_latency() {
        let addr = serve(500, "nope", 0).await;
        let check = HttpCheck {
            id: "site".to_string(),
            url: format!("http://{addr}/"),
            timeout: Duration::from_secs(2),
            body_regex: None,
        };
        let outcome = run_http_check(&check, 1_700_000_000_000).await;
        assert!(!outcome.up);
        assert_eq!(outcome.status, Some(500));
        assert!(outcome
            .samples
            .iter()
            .any(|sample| sample.name == "kestrel_http_up" && sample.value == 0.0));

        let addr = serve(200, "healthy", 250).await;
        let check = HttpCheck {
            id: "slow".to_string(),
            url: format!("http://{addr}/"),
            timeout: Duration::from_secs(2),
            body_regex: Some("healthy".to_string()),
        };
        let outcome = run_http_check(&check, 1_700_000_000_000).await;
        assert!(outcome.up);
        assert!(
            outcome.duration_seconds >= 0.2,
            "{}",
            outcome.duration_seconds
        );

        let check = HttpCheck {
            id: "miss".to_string(),
            url: format!("http://{addr}/"),
            timeout: Duration::from_secs(2),
            body_regex: Some("absent".to_string()),
        };
        let outcome = run_http_check(&check, 1_700_000_000_000).await;
        assert!(!outcome.up);
        assert!(outcome.detail.contains("body did not match"));
    }

    #[tokio::test]
    async fn http_tls_probe_records_leaf_expiry() {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let expected = expiry_from_der(cert.der()).unwrap();
        let addr = tls_serve(cert.der().to_vec(), key.serialize_der()).await;
        let expiry = RecordingVerifier::expiry_handle();
        let verifier = Arc::new(AcceptAll) as Arc<dyn ServerCertVerifier>;
        let found = probe_tls_expiry("localhost", addr.port(), verifier, Arc::clone(&expiry))
            .await
            .unwrap();
        assert_eq!(found, expected);
        let check = HttpCheck {
            id: "tls".to_string(),
            url: format!("https://localhost:{}/", addr.port()),
            timeout: Duration::from_secs(2),
            body_regex: None,
        };
        let marked = with_expiry(
            HttpOutcome {
                up: false,
                status: None,
                duration_seconds: 0.0,
                expiry_unix: None,
                detail: "probe".to_string(),
                samples: vec![],
            },
            &check,
            found,
            1_700_000_000_000,
        );
        assert!(marked
            .samples
            .iter()
            .any(|sample| sample.name == "kestrel_tls_cert_expiry_timestamp_seconds"));
    }

    async fn serve(status: u16, body: &str, delay_ms: u64) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });
        addr
    }

    async fn tls_serve(cert_der: Vec<u8>, key_der: Vec<u8>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let cert = CertificateDer::from(cert_der);
            let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("key");
            ensure_crypto_provider();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut tls,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await;
            }
        });
        addr
    }

    #[derive(Debug)]
    struct AcceptAll;

    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }
}
