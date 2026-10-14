use crate::admin;
use crate::config::{CaConfig, ServerConfigFile, TlsConfig};
use crate::start;
use kestrel_agent::config::AgentConfigFile;
use kestrel_agent::identity;
use kestrel_agent::shipper::Shipper;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use url::Url;

fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("kestrel-enrol-{label}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn server_config(dir: &Path) -> ServerConfigFile {
    ServerConfigFile {
        listen: "127.0.0.1:0".parse().unwrap(),
        ingest_listen: Some("127.0.0.1:0".parse().unwrap()),
        database_url: "postgres://kestrel:kestrel@127.0.0.1:5432/kestrel".to_string(),
        victoria_url: Url::parse("http://127.0.0.1:8428").unwrap(),
        tls: TlsConfig {
            cert_path: dir.join("server.crt"),
            key_path: dir.join("server.key"),
        },
        ca: CaConfig {
            cert_path: dir.join("ca.crt"),
            key_path: dir.join("ca.key"),
        },
        public_url: Url::parse("https://127.0.0.1/").unwrap(),
        smtp: None,
        data_dir: dir.join("data"),
    }
}

fn sample_batch() -> Vec<u8> {
    kestrel_proto::encode_batch(&kestrel_proto::v1::Batch {
        agent_id: "agent".to_string(),
        seq: 1,
        samples: vec![kestrel_proto::v1::Sample {
            name: "kestrel_up".to_string(),
            labels: vec![],
            value: 1.0,
            timestamp_ms: 1_700_000_000_000,
        }],
        ..Default::default()
    })
}

fn dev_csr() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["kestrel-agent".to_string()]).unwrap();
    params.serialize_request(&key).unwrap().pem().unwrap()
}

async fn post_enrol(addr: SocketAddr, token: &str, csr_pem: &str) -> u16 {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = client
        .post(format!("https://{addr}/api/v1/enrol"))
        .json(&serde_json::json!({
            "token": token,
            "csr_pem": csr_pem,
            "hostname": "test-host",
            "os": "test",
            "arch": "test",
        }))
        .send()
        .await
        .unwrap();
    response.status().as_u16()
}

fn assert_agent_cert(pem: &str, agent_id: &str) {
    let mut reader = pem.as_bytes();
    let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
    let life = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
    let day = 24 * 60 * 60;
    assert!(
        (89 * day..91 * day).contains(&life),
        "agent certificate lifetime was {life} seconds"
    );
    let san = cert.subject_alternative_name().unwrap().unwrap();
    let uri = format!("kestrel://agent/{agent_id}");
    let found = san.value.general_names.iter().any(
        |name| matches!(name, x509_parser::extensions::GeneralName::URI(value) if *value == uri),
    );
    assert!(found, "missing SAN {uri}");
}

fn assert_private_key(path: &Path) {
    assert!(path.is_file(), "{}", path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode {mode:o} for {}", path.display());
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("icacls")
            .arg(path)
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
}

#[tokio::test]
async fn enrol_flow_agent_ships_over_mtls() {
    let dir = scratch("flow");
    let server = tokio::time::timeout(Duration::from_secs(20), start(server_config(&dir)))
        .await
        .expect("server start timed out")
        .unwrap();
    assert_private_key(&dir.join("ca.key"));
    assert_private_key(&dir.join("server.key"));
    let token = admin::create_token(
        &dir.join("data"),
        Some("linux".to_string()),
        Duration::from_secs(3600),
    )
    .unwrap();
    let agent_dir = dir.join("agent");
    std::fs::create_dir_all(&agent_dir).unwrap();
    let agent_cfg = AgentConfigFile {
        server_url: Url::parse(&format!("https://{}/", server.addr)).unwrap(),
        data_dir: agent_dir.clone(),
        enrol_token: Some(token.clone()),
        interval_s: 30,
        buffer_max_mb: 16,
        labels: BTreeMap::new(),
        allow_remote_commands: false,
        plugin_dirs: Vec::new(),
        prometheus_listen: None,
        config_poll_s: 60,
    };
    let identity = identity::ensure(&agent_cfg).await.unwrap().unwrap();
    let stored_id = std::fs::read_to_string(agent_dir.join("agent_id")).unwrap();
    assert_eq!(stored_id.trim(), identity.agent_id);
    assert_private_key(&agent_dir.join("agent.key"));
    assert_agent_cert(&identity.cert_pem, &identity.agent_id);
    let shipper =
        Shipper::with_identity(&agent_cfg.server_url, &identity.client_identity()).unwrap();
    let status = shipper.post_bytes(sample_batch()).await.unwrap();
    assert_eq!(status, 200);

    let ingest = server.ingest_addr.expect("ingest listener");
    let open = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let denied = open
        .post(format!("https://{ingest}/api/v1/ingest"))
        .body("no-cert")
        .send()
        .await;
    assert!(
        denied.is_err(),
        "ingest listener accepted a client with no certificate"
    );
    let ingest_url = Url::parse(&format!("https://{ingest}/")).unwrap();
    let ingest_shipper = Shipper::with_identity(&ingest_url, &identity.client_identity()).unwrap();
    assert_eq!(
        ingest_shipper.post_bytes(sample_batch()).await.unwrap(),
        200
    );

    let reuse = post_enrol(server.addr, &token, &dev_csr()).await;
    assert_eq!(reuse, 401);
    admin::revoke_agent(&dir.join("data"), identity.agent_id.parse().unwrap()).unwrap();
    let revoked = shipper.post_bytes(sample_batch()).await.unwrap();
    assert_eq!(revoked, 401);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn enrol_rejects_expired_token() {
    let dir = scratch("expired");
    let server = tokio::time::timeout(Duration::from_secs(20), start(server_config(&dir)))
        .await
        .expect("server start timed out")
        .unwrap();
    let token = admin::create_token(&dir.join("data"), None, Duration::ZERO).unwrap();
    let status = post_enrol(server.addr, &token, &dev_csr()).await;
    assert_eq!(status, 401);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn enrol_rejects_reused_token() {
    let dir = scratch("reuse");
    let server = tokio::time::timeout(Duration::from_secs(20), start(server_config(&dir)))
        .await
        .expect("server start timed out")
        .unwrap();
    let token = admin::create_token(&dir.join("data"), None, Duration::from_secs(3600)).unwrap();
    let first = post_enrol(server.addr, &token, &dev_csr()).await;
    assert_eq!(first, 200);
    let second = post_enrol(server.addr, &token, &dev_csr()).await;
    assert_eq!(second, 401);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn enrol_rejects_revoked_certificate() {
    let dir = scratch("revoked");
    let server = tokio::time::timeout(Duration::from_secs(20), start(server_config(&dir)))
        .await
        .expect("server start timed out")
        .unwrap();
    let token = admin::create_token(&dir.join("data"), None, Duration::from_secs(3600)).unwrap();
    let agent_dir = dir.join("agent");
    std::fs::create_dir_all(&agent_dir).unwrap();
    let agent_cfg = AgentConfigFile {
        server_url: Url::parse(&format!("https://{}/", server.addr)).unwrap(),
        data_dir: agent_dir,
        enrol_token: Some(token),
        interval_s: 30,
        buffer_max_mb: 16,
        labels: BTreeMap::new(),
        allow_remote_commands: false,
        plugin_dirs: Vec::new(),
        prometheus_listen: None,
        config_poll_s: 60,
    };
    let identity = identity::ensure(&agent_cfg).await.unwrap().unwrap();
    let shipper =
        Shipper::with_identity(&agent_cfg.server_url, &identity.client_identity()).unwrap();
    assert_eq!(shipper.post_bytes(sample_batch()).await.unwrap(), 200);
    admin::revoke_agent(&dir.join("data"), identity.agent_id.parse().unwrap()).unwrap();
    assert_eq!(shipper.post_bytes(sample_batch()).await.unwrap(), 401);
    server.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
