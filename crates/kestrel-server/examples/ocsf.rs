//! Synthetic fixtures from the production emitters for official schema validation.
fn main() {
    let mut events = Vec::new();
    for status in ["problem", "resolved"] {
        for severity in ["info", "low", "medium", "high", "critical"] {
            events.push(kestrel_server::forward::detection_finding(
                "synthetic disk threshold",
                "synthetic-host.example.test",
                status,
                severity,
            ));
        }
    }
    for action in ["host.create", "host.read", "host.update", "host.delete"] {
        events.push(kestrel_server::forward::api_activity(
            action,
            "synthetic-operator",
            action,
        ));
    }
    println!("{}", serde_json::to_string_pretty(&events).unwrap());
}
