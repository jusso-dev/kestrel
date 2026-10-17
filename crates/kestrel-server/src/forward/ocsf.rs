//! OCSF 1.1 field names for Detection Finding (2004) and API Activity (6003).

use serde_json::{json, Value};

pub fn detection_finding(name: &str, host: &str, status: &str, severity: &str) -> Value {
    let activity_id = if status == "resolved" { 3 } else { 1 };
    json!({
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "type_uid": 2004 * 100 + activity_id,
        "type_name": if status == "resolved" { "Detection Finding: Close" } else { "Detection Finding: Create" },
        "activity_id": activity_id,
        "activity_name": if status == "resolved" { "Close" } else { "Create" },
        "severity_id": severity_id(severity),
        "severity": severity_caption(severity_id(severity)),
        "status_id": if status=="resolved"{4}else{1},
        "status": if status=="resolved"{"Resolved"}else{"New"},
        "time": chrono::Utc::now().timestamp_millis(),
        "message": format!("{name} on {host}"),
        "finding_info": {
            "uid": name,
            "title": name
        },
        "metadata": {
            "version": "1.1.0",
            "product": { "name": "Kestrel", "vendor_name": "jusso-dev" }
        },
        "resources": [{ "name": host, "type": "Host" }]
    })
}

pub fn api_activity(action: &str, actor: &str, operation: &str) -> Value {
    let (activity_id, activity_name) = if action.contains("delete") || action.ends_with("logout") {
        (4, "Delete")
    } else if action.contains("update")
        || action.contains("ack")
        || action.contains("switch")
        || action.ends_with("parent")
        || action.ends_with("link")
    {
        (3, "Update")
    } else if action.contains("read") || action.contains("list") {
        (2, "Read")
    } else {
        (1, "Create")
    };
    json!({
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "type_uid": 600300+activity_id,
        "type_name": format!("API Activity: {activity_name}"),
        "activity_id": activity_id,
        "activity_name": activity_name,
        "severity_id": 1,
        "severity": "Informational",
        "time": chrono::Utc::now().timestamp_millis(),
        "message": action,
        "api": { "operation": operation },
        "actor": { "user": { "name": actor, "type": "User" } },
        "src_endpoint": {"name":"unknown"},
        "status": "Success",
        "status_id": 1,
        "metadata": {
            "version": "1.1.0",
            "product": { "name": "Kestrel", "vendor_name": "jusso-dev" }
        }
    })
}

/// Validate Kestrel's pinned required-field emission contract, including nested
/// object types and class/activity identifiers. This does not implement every
/// optional profile in the full OCSF schema.
pub fn validate_class(value: &Value, class_uid: i64) -> Result<(), String> {
    static CONTRACT: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let contract = CONTRACT.get_or_init(|| {
        serde_json::from_str(include_str!("ocsf-1.1-required.json"))
            .expect("valid pinned OCSF contract")
    });
    if value["class_uid"].as_i64() != Some(class_uid) {
        return Err("class_uid mismatch".into());
    }
    validate_required(value, &contract["base"], "event")?;
    let class = &contract["classes"][class_uid.to_string()];
    if class.is_null() {
        return Err("unsupported OCSF class".into());
    }
    validate_required(value, class, "event")?;
    let activity = value["activity_id"].as_i64().ok_or("invalid activity_id")?;
    if value["type_uid"].as_i64() != Some(class_uid * 100 + activity) {
        return Err("type_uid does not match class/activity".into());
    }
    Ok(())
}

fn validate_required(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
    if let Some(kind) = schema["type"].as_str() {
        let valid = match kind {
            "object" => value.is_object(),
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some(),
            _ => false,
        };
        if !valid {
            return Err(format!("{path} must be {kind}"));
        }
    }
    if let Some(choices) = schema["enum"].as_array() {
        if !choices.contains(value) {
            return Err(format!("{path} has invalid value"));
        }
    }
    if let Some(required) = schema["required"].as_array() {
        for key in required.iter().filter_map(Value::as_str) {
            if value.get(key).is_none() {
                return Err(format!("missing {path}.{key}"));
            }
        }
    }
    if let Some(properties) = schema["properties"].as_object() {
        for (key, definition) in properties {
            if let Some(child) = value.get(key) {
                validate_required(child, definition, &format!("{path}.{key}"))?;
            }
        }
    }
    Ok(())
}

fn severity_id(severity: &str) -> i64 {
    match severity {
        "info" | "informational" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 3,
    }
}

fn severity_caption(id: i64) -> &'static str {
    match id {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        _ => "Unknown",
    }
}
#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn ocsf_required_contract_rejects_missing_nested_fields_and_wrong_activities() {
        let finding = detection_finding("disk", "host", "resolved", "high");
        assert_eq!(finding["activity_id"], 3);
        assert_eq!(finding["type_uid"], 200403);
        validate_class(&finding, 2004).unwrap();
        let audit = api_activity("host.create", "operator", "POST /hosts");
        validate_class(&audit, 6003).unwrap();
        for (original, class, fields) in [
            (
                &finding,
                2004,
                vec!["finding_info", "metadata", "severity_id", "time"],
            ),
            (&audit, 6003, vec!["api", "actor", "src_endpoint"]),
        ] {
            for field in fields {
                let mut invalid = original.clone();
                invalid.as_object_mut().unwrap().remove(field);
                assert!(validate_class(&invalid, class).is_err(), "{field}");
            }
        }
        let mut invalid = audit.clone();
        invalid["metadata"]["product"]["vendor_name"] = Value::Null;
        assert!(validate_class(&invalid, 6003).is_err());
        let mut invalid = finding;
        invalid["type_uid"] = json!(200402);
        assert!(validate_class(&invalid, 2004).is_err());
    }
}
