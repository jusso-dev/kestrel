//! OCSF 1.1 field names for Detection Finding (2004) and API Activity (6003).

use serde_json::{json, Value};

pub fn detection_finding(name: &str, host: &str, status: &str, severity: &str) -> Value {
    let activity_id = if status == "resolved" { 2 } else { 1 };
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
        "severity": severity,
        "status": status,
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
    json!({
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "type_uid": 600301,
        "type_name": "API Activity: Create",
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": 1,
        "severity": "Informational",
        "time": chrono::Utc::now().timestamp_millis(),
        "message": action,
        "api": { "operation": operation },
        "actor": { "user": { "name": actor, "type": "User" } },
        "status": "Success",
        "metadata": {
            "version": "1.1.0",
            "product": { "name": "Kestrel", "vendor_name": "jusso-dev" }
        }
    })
}

pub fn validate_class(value: &Value, class_uid: i64) -> Result<(), String> {
    let got = value
        .get("class_uid")
        .and_then(Value::as_i64)
        .ok_or_else(|| "missing class_uid".to_string())?;
    if got != class_uid {
        return Err(format!("class_uid {got}"));
    }
    for key in [
        "class_name",
        "category_uid",
        "category_name",
        "type_uid",
        "activity_id",
        "time",
        "metadata",
    ] {
        if value.get(key).is_none() {
            return Err(format!("missing {key}"));
        }
    }
    if class_uid == 2004 && value.get("finding_info").is_none() {
        return Err("missing finding_info".to_string());
    }
    if class_uid == 6003 && value.get("api").is_none() {
        return Err("missing api".to_string());
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
