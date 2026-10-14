//! Prometheus text exposition, used to scrape operator-configured targets
//! and to serve the agent's own `/metrics`.

use kestrel_proto::Sample;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct ExpositionSample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
    pub timestamp_ms: Option<i64>,
}

/// Parse Prometheus text. Comment and blank lines are ignored.
pub fn parse_exposition(text: &str) -> Result<Vec<ExpositionSample>, String> {
    let mut samples = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        samples.push(parse_line(line).map_err(|err| format!("line {}: {err}", index + 1))?);
    }
    Ok(samples)
}

fn parse_line(line: &str) -> Result<ExpositionSample, String> {
    let (name_and_labels, rest) = split_sample(line)?;
    let (name, labels) = if let Some(start) = name_and_labels.find('{') {
        if !name_and_labels.ends_with('}') {
            return Err("label set is not closed".to_string());
        }
        let name = name_and_labels[..start].to_string();
        let body = &name_and_labels[start + 1..name_and_labels.len() - 1];
        (name, parse_labels(body)?)
    } else {
        (name_and_labels.to_string(), Vec::new())
    };
    if !valid_name(&name) {
        return Err(format!("invalid metric name {name}"));
    }
    let mut parts = rest.split_whitespace();
    let value: f64 = parts
        .next()
        .ok_or_else(|| "missing value".to_string())?
        .parse()
        .map_err(|_| "value is not a number".to_string())?;
    if !value.is_finite() {
        return Err("value is not finite".to_string());
    }
    let timestamp_ms = match parts.next() {
        Some(raw) => Some(
            raw.parse::<i64>()
                .map_err(|_| "timestamp is not an integer".to_string())?,
        ),
        None => None,
    };
    if parts.next().is_some() {
        return Err("trailing tokens".to_string());
    }
    Ok(ExpositionSample {
        name,
        labels,
        value,
        timestamp_ms,
    })
}

fn split_sample(line: &str) -> Result<(&str, &str), String> {
    let mut quoted = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => {
                return Ok((line[..index].trim(), line[index..].trim()));
            }
            _ => {}
        }
    }
    Err("missing value".to_string())
}

fn parse_labels(body: &str) -> Result<Vec<(String, String)>, String> {
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut labels = Vec::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        rest = rest.trim_start().trim_start_matches(',');
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let eq = rest
            .find('=')
            .ok_or_else(|| "label is missing '='".to_string())?;
        let name = rest[..eq].trim();
        if !valid_name(name) {
            return Err(format!("invalid label {name}"));
        }
        let after = rest[eq + 1..].trim_start();
        let value_raw = after
            .strip_prefix('"')
            .ok_or_else(|| "label value must be quoted".to_string())?;
        let (value, next) = take_quoted(value_raw)?;
        labels.push((name.to_string(), value));
        rest = next.trim_start();
    }
    Ok(labels)
}

fn take_quoted(input: &str) -> Result<(String, &str), String> {
    let mut value = String::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => value.push('\n'),
                Some('\\') => value.push('\\'),
                Some('"') => value.push('"'),
                Some(other) => value.push(other),
                None => return Err("truncated escape".to_string()),
            }
        } else if ch == '"' {
            return Ok((value, chars.as_str()));
        } else {
            value.push(ch);
        }
    }
    Err("label value is not closed".to_string())
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_alphabetic() || ch == '_' || ch == ':' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':')
}

/// Add `job` and `instance` without replacing labels the target already set
/// under a different name. Existing `job` or `instance` labels are kept and
/// the scrape identity is added as `kestrel_job` only when the target already
/// used the name. The operator-configured identity always wins for empty targets.
pub fn relabel(samples: Vec<ExpositionSample>, job: &str, instance: &str) -> Vec<ExpositionSample> {
    samples
        .into_iter()
        .map(|mut sample| {
            if !sample.labels.iter().any(|(name, _)| name == "job") {
                sample.labels.push(("job".to_string(), job.to_string()));
            }
            if !sample.labels.iter().any(|(name, _)| name == "instance") {
                sample
                    .labels
                    .push(("instance".to_string(), instance.to_string()));
            }
            sample
        })
        .collect()
}

pub fn to_agent_samples(samples: &[ExpositionSample], now_ms: i64) -> Vec<Sample> {
    samples
        .iter()
        .map(|sample| Sample {
            name: sample.name.clone(),
            labels: sample.labels.clone(),
            value: sample.value,
            timestamp_ms: sample.timestamp_ms.unwrap_or(now_ms),
        })
        .collect()
}

/// Render samples in Prometheus text format.
pub fn encode_exposition(samples: &[Sample]) -> String {
    let mut types: BTreeMap<&str, &str> = BTreeMap::new();
    for sample in samples {
        let kind = if sample.name.ends_with("_total") {
            "counter"
        } else {
            "gauge"
        };
        types.entry(sample.name.as_str()).or_insert(kind);
    }
    let mut out = String::new();
    for (name, kind) in types {
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push(' ');
        out.push_str(kind);
        out.push('\n');
    }
    for sample in samples {
        out.push_str(&sample.name);
        if !sample.labels.is_empty() {
            out.push('{');
            for (index, (key, value)) in sample.labels.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(key);
                out.push_str("=\"");
                out.push_str(&escape_label(value));
                out.push('"');
            }
            out.push('}');
        }
        out.push(' ');
        out.push_str(&sample.value.to_string());
        out.push(' ');
        out.push_str(&sample.timestamp_ms.to_string());
        out.push('\n');
    }
    out
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Structural checks similar to `promtool check metrics`.
pub fn validate_exposition(text: &str) -> Result<(), String> {
    let mut seen_help = BTreeMap::<String, ()>::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            if !valid_name(name) {
                return Err(format!("bad HELP name {name}"));
            }
            if seen_help.insert(name.to_string(), ()).is_some() {
                return Err(format!("duplicate HELP for {name}"));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or("");
            let kind = parts.next().unwrap_or("");
            if !valid_name(name) {
                return Err(format!("bad TYPE name {name}"));
            }
            if !matches!(
                kind,
                "counter" | "gauge" | "histogram" | "summary" | "untyped"
            ) {
                return Err(format!("bad TYPE kind {kind}"));
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        parse_line(line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prom_scrape_parses_node_exporter_style_text() {
        let text = r#"
# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 100.5
node_filesystem_avail_bytes{mountpoint="/"} 1024
"#;
        let parsed = parse_exposition(text).unwrap();
        assert_eq!(parsed.len(), 2);
        let relabelled = relabel(parsed, "node", "web:9100");
        assert!(relabelled[0]
            .labels
            .iter()
            .any(|(name, value)| name == "job" && value == "node"));
        assert!(relabelled[0]
            .labels
            .iter()
            .any(|(name, value)| name == "instance" && value == "web:9100"));
        assert_eq!(relabelled[0].value, 100.5);
    }

    #[test]
    fn prom_encode_validates() {
        let samples = vec![Sample {
            name: "kestrel_uptime_seconds".to_string(),
            labels: vec![("host".to_string(), "web".to_string())],
            value: 12.0,
            timestamp_ms: 1_700_000_000_000,
        }];
        let text = encode_exposition(&samples);
        validate_exposition(&text).unwrap();
        let parsed = parse_exposition(&text).unwrap();
        assert_eq!(parsed[0].name, "kestrel_uptime_seconds");
        assert_eq!(parsed[0].value, 12.0);
    }
}
