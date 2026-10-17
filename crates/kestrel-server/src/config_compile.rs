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
    let mut configured_items = Vec::new();
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
            _ => configured_items.push(kestrel_proto::v1::ItemSpec {
                key: item.key.clone(),
                kind: item.kind.clone(),
                interval_s: item.interval_s.max(1),
                params_json: item.params.to_string(),
            }),
        }
    }
    let mut config = AgentConfig {
        interval_s: interval,
        checks,
        logs,
        etag: String::new(),
        items: configured_items,
    };
    let etag = etag_of(&config);
    config.etag = etag.clone();
    (config, etag)
}

fn etag_of(config: &AgentConfig) -> String {
    use prost::Message;
    let mut hasher = Sha256::new();
    // Length-delimited protobuf fields distinguish argument boundaries and cover
    // every effective setting, including timeouts and item parameters.
    hasher.update(config.encode_to_vec());
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
    let mut tx = db.pool.begin().await.map_err(crate::db::db_err)?;
    seed_builtin_templates(&mut tx, crate::store::DEFAULT_TENANT_ID).await?;
    tx.commit().await.map_err(crate::db::db_err)
}

pub(crate) async fn seed_builtin_templates(
    conn: &mut sqlx::PgConnection,
    tenant: uuid::Uuid,
) -> Result<(), crate::ServerError> {
    for doc in builtin_templates() {
        let id:Option<uuid::Uuid>=sqlx::query_scalar("INSERT INTO templates (tenant_id,name,description) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,name) DO NOTHING RETURNING id").bind(tenant).bind(doc.name).bind(doc.description).fetch_optional(&mut *conn).await.map_err(crate::db::db_err)?;
        let Some(id) = id else {
            continue;
        };
        for item in doc.items {
            sqlx::query("INSERT INTO items (tenant_id,template_id,key,kind,interval_s,params) VALUES ($1,$2,$3,$4,$5,$6)").bind(tenant).bind(id).bind(item.key).bind(item.kind).bind(item.interval_s as i32).bind(item.params).execute(&mut *conn).await.map_err(crate::db::db_err)?;
        }
        for trigger in doc.triggers {
            sqlx::query("INSERT INTO triggers (tenant_id,template_id,name,expression,severity,for_seconds) VALUES ($1,$2,$3,$4,$5,$6)").bind(tenant).bind(id).bind(trigger.name).bind(trigger.expression).bind(trigger.severity).bind(trigger.for_seconds as i32).execute(&mut *conn).await.map_err(crate::db::db_err)?;
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
    fn config_compile_etag_covers_timeouts_item_params_and_argument_boundaries() {
        let host = HostView {
            name: "host".into(),
            overrides: BTreeMap::new(),
        };
        let mut template = TemplateDoc {
            name: "checks".into(),
            description: String::new(),
            items: vec![ItemSpec {
                key: "command".into(),
                kind: "command".into(),
                interval_s: 30,
                params: serde_json::json!({"command":["ab","c"],"timeout_s":5}),
            }],
            triggers: vec![],
        };
        let (_, first) = compile_agent_config(&host, &[template.clone()]);
        template.items[0].params["command"] = serde_json::json!(["a", "bc"]);
        let (_, second) = compile_agent_config(&host, &[template.clone()]);
        assert_ne!(first, second);
        template.items[0].params["timeout_s"] = serde_json::json!(10);
        let (_, third) = compile_agent_config(&host, &[template.clone()]);
        assert_ne!(second, third);
        template.items[0].kind = "http".into();
        template.items[0].params = serde_json::json!({"url":"https://first.test"});
        let (_, fourth) = compile_agent_config(&host, &[template.clone()]);
        template.items[0].params["url"] = serde_json::json!("https://second.test");
        assert_ne!(fourth, compile_agent_config(&host, &[template]).1);
    }

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
