//! Compile host templates into the agent config returned with an ETag.

use kestrel_proto::v1::{AgentConfig, CheckSpec, LogSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSpec {
    pub key: String,
    pub kind: String,
    pub interval_s: u32,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerSpec {
    pub name: String,
    pub expression: String,
    pub severity: String,
    pub for_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateDoc {
    pub name: String,
    pub description: String,
    pub items: Vec<ItemSpec>,
    pub triggers: Vec<TriggerSpec>,
}

#[derive(Debug, Clone)]
pub struct HostView {
    pub name: String,
    pub overrides: BTreeMap<String, ItemSpec>,
}

pub fn compile_agent_config(host: &HostView, templates: &[TemplateDoc]) -> (AgentConfig, String) {
    let mut items: BTreeMap<String, ItemSpec> = BTreeMap::new();
    for template in templates {
        for item in &template.items {
            items.insert(item.key.clone(), item.clone());
        }
    }
    for (key, item) in &host.overrides {
        items.insert(key.clone(), item.clone());
    }
    let mut checks = Vec::new();
    let mut logs = Vec::new();
    let mut interval = 30u32;
    for item in items.values() {
        interval = interval.min(item.interval_s.max(1));
        match item.kind.as_str() {
            "command" => {
                let command = item
                    .params
                    .get("command")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if command.is_empty() {
                    continue;
                }
                checks.push(CheckSpec {
                    id: item.key.clone(),
                    command,
                    interval_s: item.interval_s,
                    timeout_s: item
                        .params
                        .get("timeout_s")
                        .and_then(Value::as_u64)
                        .unwrap_or(10) as u32,
                });
            }
            "log" => {
                if let Some(path) = item.params.get("path").and_then(Value::as_str) {
                    logs.push(LogSpec {
                        path: path.to_string(),
                        pattern: item
                            .params
                            .get("pattern")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    let mut config = AgentConfig {
        interval_s: interval,
        checks,
        logs,
        etag: String::new(),
    };
    let etag = etag_of(&config);
    config.etag = etag.clone();
    (config, etag)
}

fn etag_of(config: &AgentConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(config.interval_s.to_string().as_bytes());
    for check in &config.checks {
        hasher.update(check.id.as_bytes());
        hasher.update(check.interval_s.to_string().as_bytes());
        for arg in &check.command {
            hasher.update(arg.as_bytes());
        }
    }
    for log in &config.logs {
        hasher.update(log.path.as_bytes());
        hasher.update(log.pattern.as_bytes());
    }
    format!(
        "\"{}\"",
        data_encoding::HEXLOWER.encode(hasher.finalize().as_slice())
    )
}

pub fn template_to_yaml(doc: &TemplateDoc) -> Result<String, String> {
    serde_yaml::to_string(doc).map_err(|err| err.to_string())
}

pub fn template_from_yaml(text: &str) -> Result<TemplateDoc, String> {
    serde_yaml::from_str(text).map_err(|err| err.to_string())
}

pub fn builtin_templates() -> Vec<TemplateDoc> {
    vec![
        include_str!("../templates/linux.yaml"),
        include_str!("../templates/windows.yaml"),
        include_str!("../templates/macos.yaml"),
        include_str!("../templates/postgresql.yaml"),
        include_str!("../templates/nginx.yaml"),
        include_str!("../templates/snmp-generic.yaml"),
        include_str!("../templates/snmp-if-mib.yaml"),
        include_str!("../templates/snmp-ups-mib.yaml"),
    ]
    .into_iter()
    .map(|text| template_from_yaml(text).expect("built-in template"))
    .collect()
}

pub async fn ensure_builtin_templates(db: &crate::db::Db) -> Result<(), crate::ServerError> {
    let tenant = crate::db::TenantId::default_tenant();
    let existing = db.list_templates(&tenant).await?;
    for doc in builtin_templates() {
        if existing.iter().any(|template| template.name == doc.name) {
            continue;
        }
        let template = db
            .insert_template(
                &tenant,
                crate::db::NewTemplate {
                    name: doc.name,
                    description: doc.description,
                },
            )
            .await?;
        for item in doc.items {
            db.insert_item(
                &tenant,
                crate::db::NewItem {
                    template_id: template.id,
                    key: item.key,
                    kind: item.kind,
                    interval_s: i32::try_from(item.interval_s).unwrap_or(30),
                    params: item.params,
                },
            )
            .await?;
        }
        for trigger in doc.triggers {
            db.insert_trigger(
                &tenant,
                crate::db::NewTrigger {
                    template_id: Some(template.id),
                    host_id: None,
                    name: trigger.name,
                    expression: trigger.expression,
                    severity: trigger.severity,
                    for_seconds: i32::try_from(trigger.for_seconds).unwrap_or(0),
                    recovery_expr: None,
                    labels: serde_json::json!({}),
                },
            )
            .await?;
        }
    }
    Ok(())
}

pub fn template_names(docs: &[TemplateDoc]) -> BTreeSet<String> {
    docs.iter().map(|doc| doc.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_compile_is_stable_and_yaml_round_trips() {
        let linux = builtin_templates()
            .into_iter()
            .find(|doc| doc.name == "Linux")
            .unwrap();
        assert!(linux
            .triggers
            .iter()
            .any(|trigger| trigger.expression.contains("0.9")));
        assert!(linux.triggers.iter().any(|trigger| trigger
            .expression
            .contains("kestrel_agent_last_seen_timestamp")));
        let host = HostView {
            name: "web-1".to_string(),
            overrides: BTreeMap::new(),
        };
        let (config, etag) = compile_agent_config(&host, std::slice::from_ref(&linux));
        assert_eq!(config.etag, etag);
        assert!(etag.starts_with('"'));
        let again = template_from_yaml(&template_to_yaml(&linux).unwrap()).unwrap();
        assert_eq!(again, linux);
    }
}
