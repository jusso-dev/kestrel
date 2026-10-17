//! Low-level discovery. Prototypes use `{#MOUNT}` style macros.

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;

pub fn expand_macros(prototype: &str, labels: &BTreeMap<String, String>) -> String {
    let mut out = prototype.to_string();
    for (key, value) in labels {
        out = out.replace(&format!("{{#{key}}}"), value);
    }
    out
}

pub fn entity_lost(last_seen: DateTime<Utc>, now: DateTime<Utc>, keep_days: i64) -> bool {
    now.signed_duration_since(last_seen) > Duration::days(keep_days.max(0))
}

pub fn filter_matches(value: &str, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    if filter.len() > 200 {
        return false;
    }
    Regex::new(filter)
        .map(|regex| regex.is_match(value))
        .unwrap_or(false)
}

pub fn prototype_item(prototype: &str, labels: &BTreeMap<String, String>) -> Value {
    fn expand(value: &mut Value, labels: &BTreeMap<String, String>, expression: bool) {
        match value {
            Value::String(text) => {
                let replacements = labels
                    .iter()
                    .map(|(key, value)| {
                        let replacement = if expression {
                            let quoted = serde_json::to_string(value).unwrap();
                            quoted[1..quoted.len() - 1].to_string()
                        } else {
                            value.clone()
                        };
                        (key.clone(), replacement)
                    })
                    .collect();
                *text = expand_macros(text, &replacements);
            }
            Value::Object(object) => {
                for (key, value) in object {
                    expand(value, labels, key == "expression" || key == "recovery_expr");
                }
            }
            Value::Array(values) => {
                for value in values {
                    expand(value, labels, expression);
                }
            }
            _ => {}
        }
    }
    let Ok(mut value) = serde_json::from_str::<Value>(prototype) else {
        return Value::String(expand_macros(prototype, labels));
    };
    expand(&mut value, labels, false);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_labels_cannot_escape_json_or_promql_strings() {
        let labels = BTreeMap::from([(
            "MOUNT".to_string(),
            "/data\"} or evil{host=\"other".to_string(),
        )]);
        let prototype=serde_json::json!({"key":"disk[{#MOUNT}]","expression":"metric{mount=\"{#MOUNT}\"} > 0"}).to_string();
        let item = prototype_item(&prototype, &labels);
        assert!(item.is_object());
        let expression = item["expression"].as_str().unwrap();
        assert!(expression.contains("\\\""));
        assert!(crate::promql::inject_scope(expression, "tenant", None).is_ok());
    }

    #[test]
    fn discovery_expands_mount_macros_and_drops_lost_entities() {
        let mut labels = BTreeMap::new();
        labels.insert("MOUNT".to_string(), "/data".to_string());
        let item = expand_macros(
            r#"{"key":"fs.free[{#MOUNT}]","expr":"kestrel_filesystem_free_bytes{mount=\"{#MOUNT}\"} < 1"}"#,
            &labels,
        );
        assert!(item.contains("/data"));
        assert!(!item.contains("{#MOUNT}"));
        assert!(filter_matches("/data", "^/data"));
        assert!(!filter_matches("/var", "^/data"));
        let seen = Utc::now() - Duration::days(8);
        assert!(entity_lost(seen, Utc::now(), 7));
        assert!(!entity_lost(Utc::now() - Duration::days(1), Utc::now(), 7));
    }
}
