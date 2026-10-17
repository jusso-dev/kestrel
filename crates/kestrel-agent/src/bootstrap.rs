//! First-run configuration without putting enrolment tokens in command lines.

use crate::{config, perms};
use std::io::{self, Read};
use std::path::PathBuf;

pub fn configure(args: &[String], input: impl Read) -> Result<PathBuf, String> {
    if !args.iter().any(|arg| arg == "--token-stdin") {
        return Err("--configure requires --token-stdin".into());
    }
    let value = |flag: &str| {
        args.windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
    };
    let server = value("--server").ok_or("--configure requires --server URL")?;
    let server: url::Url = server.parse().map_err(|_| "invalid server URL")?;
    if server.scheme() != "https"
        && !(server.scheme() == "http"
            && server.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }))
    {
        return Err("server URL must use HTTPS (HTTP is allowed for loopback development)".into());
    }
    if !server.username().is_empty()
        || server.password().is_some()
        || server.query().is_some()
        || server.fragment().is_some()
    {
        return Err("server URL must not include credentials, a query, or a fragment".into());
    }
    let path = value("--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| config::default_config_path(config::Platform::current()));
    if path.exists() {
        return Err(format!(
            "{} already exists; edit the existing configuration",
            path.display()
        ));
    }
    let data_dir = value("--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);
    let mut token = String::new();
    input
        .take(16 * 1024 + 1)
        .read_to_string(&mut token)
        .map_err(|_| "could not read enrolment token from stdin")?;
    let token = token.trim();
    if token.is_empty() || token.len() > 16 * 1024 || token.chars().any(char::is_control) {
        return Err("stdin must contain one non-empty enrolment token (at most 16 KiB)".into());
    }
    let quoted = |value: &str| serde_json::to_string(value).expect("string serialization");
    let mut body = format!(
        "server_url = {}\ndata_dir = {}\nenrol_token = {}\ninterval_s = 30\n",
        quoted(server.as_str()),
        quoted(&data_dir.to_string_lossy()),
        quoted(token)
    );
    if let Some(ca_file) = value("--ca-file") {
        let pem = std::fs::read(&ca_file).map_err(|_| "could not read bootstrap CA file")?;
        let certificates =
            reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| "invalid bootstrap CA PEM")?;
        if certificates.is_empty() {
            return Err("bootstrap CA file contains no certificates".into());
        }
        let destination = path.with_file_name("bootstrap-ca.crt");
        let text = std::str::from_utf8(&pem).map_err(|_| "bootstrap CA file must be PEM")?;
        perms::write_certificate(&destination, text)
            .map_err(|err| format!("could not save bootstrap CA: {err}"))?;
        body.push_str(&format!(
            "bootstrap_ca_path = {}\n",
            quoted(&destination.to_string_lossy())
        ));
    }
    std::fs::create_dir_all(&data_dir)
        .map_err(|err| format!("could not create data directory: {err}"))?;
    perms::write_private_key(&path, &body)
        .map_err(|err| format!("could not write protected agent configuration: {err}"))?;
    Ok(path)
}

fn default_data_dir() -> PathBuf {
    match config::Platform::current() {
        config::Platform::Linux => PathBuf::from("/var/lib/kestrel"),
        config::Platform::Macos => PathBuf::from("/Library/Application Support/Kestrel"),
        config::Platform::Windows => PathBuf::from(r"C:\ProgramData\Kestrel"),
    }
}

pub fn from_stdin(args: &[String]) -> Result<PathBuf, String> {
    configure(args, io::stdin().lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::Format;
    #[test]
    fn configure_writes_protected_parseable_config_without_clobbering() {
        let dir = std::env::temp_dir().join(format!("kestrel-bootstrap-{}", uuid::Uuid::new_v4()));
        let path = dir.join("agent.toml");
        let args = vec![
            "--configure".into(),
            "--server".into(),
            "https://monitor.example/".into(),
            "--token-stdin".into(),
            "--config".into(),
            path.display().to_string(),
            "--data-dir".into(),
            dir.join("data").display().to_string(),
        ];
        configure(&args, "example-test-token\n".as_bytes()).unwrap();
        let cfg: config::AgentConfigFile =
            figment::Figment::from(figment::providers::Toml::file(&path))
                .extract()
                .unwrap();
        assert_eq!(cfg.enrol_token.as_deref(), Some("example-test-token"));
        assert!(configure(&args, "replacement".as_bytes())
            .unwrap_err()
            .contains("already exists"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
