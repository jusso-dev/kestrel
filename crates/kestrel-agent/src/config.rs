//! Agent TOML configuration with `KESTREL_` environment overrides.

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;
use std::collections::BTreeMap;
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

/// Default agent configuration path for `platform`.
pub fn default_config_path(platform: Platform) -> PathBuf {
    match platform {
        Platform::Linux => PathBuf::from("/etc/kestrel/agent.toml"),
        Platform::Macos => PathBuf::from("/Library/Application Support/Kestrel/agent.toml"),
        Platform::Windows => PathBuf::from(r"C:\ProgramData\Kestrel\agent.toml"),
    }
}

fn default_interval_s() -> u32 {
    30
}

fn default_buffer_max_mb() -> u64 {
    256
}

/// On-disk agent configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentConfigFile {
    pub server_url: Url,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub enrol_token: Option<String>,
    #[serde(default = "default_interval_s")]
    pub interval_s: u32,
    #[serde(default = "default_buffer_max_mb")]
    pub buffer_max_mb: u64,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub allow_remote_commands: bool,
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
/// A missing file is treated as empty so a missing required field is reported
/// by name instead of as a file-not-found error.
pub fn load_agent_config(path: &Path) -> Result<AgentConfigFile, ConfigError> {
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
/// `KESTREL_LOG` wins over `RUST_LOG`. A second call is ignored so tests and
/// the binary can both initialise logging.
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

    #[test]
    fn default_paths_follow_the_platform() {
        assert_eq!(
            default_config_path(Platform::Linux),
            PathBuf::from("/etc/kestrel/agent.toml")
        );
        assert_eq!(
            default_config_path(Platform::Macos),
            PathBuf::from("/Library/Application Support/Kestrel/agent.toml")
        );
        assert_eq!(
            default_config_path(Platform::Windows),
            PathBuf::from(r"C:\ProgramData\Kestrel\agent.toml")
        );
    }

    #[test]
    fn config_flag_overrides_the_default_path() {
        let path = config_path_from_args(["--config", "custom.toml"]);
        assert_eq!(path, PathBuf::from("custom.toml"));
        let path = config_path_from_args(["--config=other.toml"]);
        assert_eq!(path, PathBuf::from("other.toml"));
    }

    #[test]
    fn config_env_override_and_defaults() {
        with_jail(|jail| {
            jail.create_file(
                "agent.toml",
                r#"
server_url = "https://kestrel.example:8443"
data_dir = "/var/lib/kestrel"
"#,
            )
            .unwrap();
            jail.set_env("KESTREL_INTERVAL_S", "15");
            jail.set_env("KESTREL_SERVER_URL", "https://override.example");
            jail.set_env("KESTREL_LABELS__ROLE", "edge");
            let cfg = load_agent_config(&jail.directory().join("agent.toml")).unwrap();
            assert_eq!(cfg.server_url.as_str(), "https://override.example/");
            assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/kestrel"));
            assert_eq!(cfg.interval_s, 15);
            assert_eq!(cfg.buffer_max_mb, 256);
            assert!(!cfg.allow_remote_commands);
            assert_eq!(cfg.enrol_token, None);
            assert_eq!(cfg.labels.get("role").map(String::as_str), Some("edge"));
        });
    }

    #[test]
    fn config_missing_field_names_the_field() {
        with_jail(|jail| {
            jail.create_file("agent.toml", "interval_s = 10\n").unwrap();
            let err = load_agent_config(&jail.directory().join("agent.toml")).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("server_url"),
                "error should name the field, got {message}"
            );
        });
    }

    #[test]
    fn dev_example_parses() {
        with_jail(|_jail| {
            let path =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev/agent.toml");
            let cfg = load_agent_config(&path).unwrap();
            assert_eq!(cfg.interval_s, 30);
            assert!(!cfg.allow_remote_commands);
        });
    }
}
