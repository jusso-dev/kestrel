//! Server TOML configuration with `KESTREL_` environment overrides.

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use url::Url;

/// Operating system used to pick the default configuration path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
    Windows,
}

impl Platform {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "windows" => Self::Windows,
            "macos" => Self::Macos,
            _ => Self::Linux,
        }
    }
}

/// Default server configuration path for `platform`.
pub fn default_config_path(platform: Platform) -> PathBuf {
    match platform {
        Platform::Linux => PathBuf::from("/etc/kestrel/server.toml"),
        Platform::Macos => PathBuf::from("/Library/Application Support/Kestrel/server.toml"),
        Platform::Windows => PathBuf::from(r"C:\ProgramData\Kestrel\server.toml"),
    }
}

fn default_data_dir() -> PathBuf {
    match Platform::current() {
        Platform::Linux => PathBuf::from("/var/lib/kestrel"),
        Platform::Macos => PathBuf::from("/Library/Application Support/Kestrel"),
        Platform::Windows => PathBuf::from(r"C:\ProgramData\Kestrel\data"),
    }
}

/// TLS certificate and private key for the public listener.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Internal CA material. When the files are absent the server creates them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CaConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// SMTP settings for email notifications. `starttls` defaults to true.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    pub from: String,
    #[serde(default = "default_starttls")]
    pub starttls: bool,
}

fn default_starttls() -> bool {
    true
}

/// On-disk server configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerConfigFile {
    pub listen: SocketAddr,
    #[serde(default)]
    pub ingest_listen: Option<SocketAddr>,
    pub database_url: String,
    pub victoria_url: Url,
    pub tls: TlsConfig,
    pub ca: CaConfig,
    pub public_url: Url,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: u32,
    #[serde(default = "default_otlp_drop_attributes")]
    pub otlp_drop_attributes: Vec<String>,
    /// Let tenant-configured HTTP checks, scrapes and webhooks reach loopback.
    /// Off by default; see `docs/operations.md`.
    #[serde(default)]
    pub allow_loopback_targets: bool,
}

fn default_log_retention_days() -> u32 {
    7
}
fn default_otlp_drop_attributes() -> Vec<String> {
    vec!["user_id".to_string()]
}

/// Configuration could not be loaded. The message names the missing field.
#[derive(Debug)]
pub struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// `--config <path>` or `--config=<path>` from `args`, otherwise the platform default.
pub fn config_path_from_args(args: impl IntoIterator<Item = impl AsRef<str>>) -> PathBuf {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if let Some(value) = arg.strip_prefix("--config=") {
            return PathBuf::from(value);
        }
        if arg == "--config" {
            if let Some(value) = args.next() {
                return PathBuf::from(value.as_ref());
            }
        }
    }
    default_config_path(Platform::current())
}

/// Load `path` (when it exists) and apply `KESTREL_` environment overrides.
///
/// Nested keys use `__`, so `KESTREL_TLS__CERT_PATH` sets `tls.cert_path`.
/// A missing file is treated as empty so a missing required field is reported
/// by name.
pub fn load_server_config(path: &Path) -> Result<ServerConfigFile, ConfigError> {
    let mut figment = Figment::new();
    if path.is_file() {
        figment = figment.merge(Toml::file(path));
    }
    figment
        .merge(Env::prefixed("KESTREL_").split("__"))
        .extract()
        .map_err(|err| ConfigError(format!("{} ({})", err, path.display())))
}

/// Install a process-wide tracing subscriber.
///
/// `KESTREL_LOG` wins over `RUST_LOG`. A second call is ignored.
pub fn init_tracing() {
    let directive = std::env::var("KESTREL_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());
    let filter = tracing_subscriber::EnvFilter::try_new(directive)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `figment::Jail` closures must return `figment::Result`, whose error is
    /// larger than Clippy's threshold. The allow sits on this wrapper.
    #[allow(clippy::result_large_err)]
    fn with_jail(f: impl FnOnce(&mut figment::Jail)) {
        figment::Jail::expect_with(|jail| {
            f(jail);
            Ok(())
        });
    }

    const MINIMAL: &str = r#"
listen = "127.0.0.1:8080"
database_url = "postgres://kestrel:kestrel@localhost/kestrel"
victoria_url = "http://localhost:8428"
public_url = "http://127.0.0.1:8080"

[tls]
cert_path = "server.crt"
key_path = "server.key"

[ca]
cert_path = "ca.crt"
key_path = "ca.key"
"#;

    #[test]
    fn listen_env_overrides_file() {
        with_jail(|jail| {
            jail.create_file("server.toml", MINIMAL).unwrap();
            jail.set_env("KESTREL_LISTEN", "0.0.0.0:9000");
            let cfg = load_server_config(&jail.directory().join("server.toml")).unwrap();
            assert_eq!(cfg.listen, "0.0.0.0:9000".parse().unwrap());
            assert_eq!(
                cfg.database_url,
                "postgres://kestrel:kestrel@localhost/kestrel"
            );
        });
    }

    #[test]
    fn nested_env_overrides_tls_path() {
        with_jail(|jail| {
            jail.create_file("server.toml", MINIMAL).unwrap();
            jail.set_env("KESTREL_TLS__CERT_PATH", "override.crt");
            let cfg = load_server_config(&jail.directory().join("server.toml")).unwrap();
            assert_eq!(cfg.tls.cert_path, PathBuf::from("override.crt"));
            assert_eq!(cfg.tls.key_path, PathBuf::from("server.key"));
        });
    }

    #[test]
    fn missing_field_names_the_field() {
        with_jail(|jail| {
            jail.create_file(
                "server.toml",
                r#"
listen = "127.0.0.1:8080"
victoria_url = "http://localhost:8428"
public_url = "http://127.0.0.1:8080"

[tls]
cert_path = "server.crt"
key_path = "server.key"

[ca]
cert_path = "ca.crt"
key_path = "ca.key"
"#,
            )
            .unwrap();
            let err = load_server_config(&jail.directory().join("server.toml")).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("database_url"),
                "error should name the field, got {message}"
            );
        });
    }

    #[test]
    fn absent_file_names_a_required_field() {
        with_jail(|jail| {
            let err = load_server_config(&jail.directory().join("missing.toml")).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("listen"),
                "error should name the field, got {message}"
            );
        });
    }

    #[test]
    fn dev_example_parses() {
        with_jail(|_jail| {
            let path =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev/server.toml");
            let cfg = load_server_config(&path).unwrap();
            assert_eq!(cfg.listen.port(), 8080);
            assert!(cfg.smtp.is_some());
        });
    }
}
