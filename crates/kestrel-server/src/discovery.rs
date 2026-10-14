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
    let expanded = expand_macros(prototype, labels);
    serde_json::from_str(&expanded).unwrap_or(Value::String(expanded))
}

#[cfg(test)]
mod tests {
    use super::*;

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
