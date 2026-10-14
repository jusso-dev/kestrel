//! Desired config from the server, inventory, and operator-configured checks.
//!
//! Script checks run only when `allow_remote_commands` is true and the
//! executable is inside a configured plugin directory. HTTP checks from a
//! linked template are not shell commands.

use crate::config::AgentConfigFile;
use kestrel_checks::{resolve_executable, CommandCheck};
use kestrel_proto::v1::{self, Inventory};
use std::time::Duration;

pub fn config_url(server: &url::Url) -> String {
    let mut url = server.clone();
    let path = url.path().trim_end_matches('/');
    url.set_path(&format!("{path}/api/v1/agent/config"));
    url.to_string()
}

pub fn prometheus_bind_allowed(addr: &str) -> bool {
    let addr = addr.trim();
    addr.starts_with("127.0.0.1:") || addr.starts_with("localhost:") || addr.starts_with("[::1]:")
}

pub fn command_allowed(cfg: &AgentConfigFile, argv: &[String]) -> bool {
    if !cfg.allow_remote_commands || argv.is_empty() || cfg.plugin_dirs.is_empty() {
        return false;
    }
    resolve_executable(argv, &cfg.plugin_dirs).is_ok()
}

pub fn checks_from_config(cfg: &AgentConfigFile, desired: &v1::AgentConfig) -> Vec<CommandCheck> {
    desired
        .checks
        .iter()
        .filter(|spec| command_allowed(cfg, &spec.command))
        .map(|spec| CommandCheck {
            id: spec.id.clone(),
            command: spec.command.clone(),
            timeout: Duration::from_secs(u64::from(spec.timeout_s.max(1))),
            interval: Duration::from_secs(u64::from(spec.interval_s.max(1))),
        })
        .collect()
}

pub fn inventory_changed(previous: &str, next: &Inventory) -> bool {
    let encoded = format!("{next:?}");
    encoded != previous
}

pub fn http_check_is_not_a_shell(kind: &str) -> bool {
    kind == "http" || kind == "builtin" || kind == "snmp"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cfg(allow: bool) -> AgentConfigFile {
        AgentConfigFile {
            server_url: url::Url::parse("https://kestrel.example/").unwrap(),
            data_dir: std::path::PathBuf::from("/var/lib/kestrel"),
            enrol_token: None,
            interval_s: 30,
            buffer_max_mb: 16,
            labels: BTreeMap::new(),
            allow_remote_commands: allow,
            plugin_dirs: vec![std::path::PathBuf::from("/usr/lib/kestrel/plugins")],
            prometheus_listen: Some("127.0.0.1:9469".to_string()),
            config_poll_s: 60,
        }
    }

    #[test]
    fn desired_config_refuses_commands_unless_the_operator_enabled_them() {
        let spec = v1::AgentConfig {
            interval_s: 30,
            checks: vec![v1::CheckSpec {
                id: "disk".to_string(),
                command: vec!["/bin/echo".to_string()],
                interval_s: 30,
                timeout_s: 5,
            }],
            logs: vec![],
            etag: "\"abc\"".to_string(),
        };
        assert!(checks_from_config(&cfg(false), &spec).is_empty());
        assert!(checks_from_config(&cfg(true), &spec).is_empty());
        assert!(!prometheus_bind_allowed("0.0.0.0:9469"));
        assert!(prometheus_bind_allowed("127.0.0.1:9469"));
        assert!(http_check_is_not_a_shell("http"));
        assert_eq!(
            config_url(&url::Url::parse("https://kestrel.example/base/").unwrap()),
            "https://kestrel.example/base/api/v1/agent/config"
        );
        let inventory = Inventory::default();
        assert!(inventory_changed("previous", &inventory));
        assert!(!inventory_changed(&format!("{inventory:?}"), &inventory));
    }
}
