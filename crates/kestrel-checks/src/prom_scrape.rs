//! Prometheus text exposition, used to scrape operator-configured targets
//! and to serve the agent's own `/metrics`.

use kestrel_proto::Sample;
use std::collections::BTreeMap;
use std::time::Duration;

/// Scrape an HTTP endpoint with a time and body bound, retaining valid finite
/// observations when an exporter reports NaN for unavailable measurements.
pub async fn scrape_prometheus(
    url: &str,
    job: &str,
    instance: &str,
    timeout: Duration,
    now_ms: i64,
) -> Result<Vec<Sample>, String> {
    scrape_prometheus_guarded(url, job, instance, timeout, now_ms, None).await
}

/// [`scrape_prometheus`] with connections restricted by `egress` when present.
pub async fn scrape_prometheus_guarded(
    url: &str,
    job: &str,
    instance: &str,
    timeout: Duration,
    now_ms: i64,
    egress: Option<&std::sync::Arc<crate::EgressGuard>>,
) -> Result<Vec<Sample>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "invalid scrape URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("scrape URL must use HTTP(S) without embedded credentials".into());
    }
    let mut builder = reqwest::Client::builder()
        .timeout(timeout.max(Duration::from_millis(1)))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(egress) = egress {
        builder = egress.apply(builder, url).await?;
    }
    let client = builder.build().map_err(|err| err.to_string())?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|err| err.without_url().to_string())?
        .error_for_status()
        .map_err(|err| err.without_url().to_string())?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| err.without_url().to_string())?
    {
        if body.len() + chunk.len() > 16 * 1024 * 1024 {
            return Err("scrape exceeds 16 MiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    let parsed =
        parse_exposition(std::str::from_utf8(&body).map_err(|_| "scrape body is not UTF-8")?)?;
    let identity = if instance.is_empty() {
        crate::http::metric_target(url)
    } else {
        instance.to_string()
    };
    Ok(to_agent_samples(&relabel(parsed, job, &identity), now_ms))
}

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
    let mut escaped = false;
    let mut braces = 0u8;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '{' if !quoted => braces = braces.saturating_add(1),
            '}' if !quoted => braces = braces.saturating_sub(1),
            ' ' | '\t' if !quoted && braces == 0 => {
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
        let eq = rest
            .find('=')
            .ok_or_else(|| "label is missing '='".to_string())?;
        let name = rest[..eq].trim();
        if !valid_name(name) || name.contains(':') || labels.iter().any(|(key, _)| key == name) {
            return Err(format!("invalid label {name}"));
        }
        let after = rest[eq + 1..].trim_start();
        let value_raw = after
            .strip_prefix('"')
            .ok_or_else(|| "label value must be quoted".to_string())?;
        let (value, next) = take_quoted(value_raw)?;
        labels.push((name.to_string(), value));
        rest = next.trim_start();
        if !rest.is_empty() {
            rest = rest
                .strip_prefix(',')
                .ok_or_else(|| "labels must be comma separated".to_string())?
                .trim_start();
        }
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
                Some(_) => return Err("invalid label escape".to_string()),
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

/// Apply the configured scrape identity, preserving conflicting target labels
/// under `exported_` names as Prometheus does when honor_labels is false.
pub fn relabel(samples: Vec<ExpositionSample>, job: &str, instance: &str) -> Vec<ExpositionSample> {
    samples
        .into_iter()
        .map(|mut sample| {
            for (key, value) in [("job", job), ("instance", instance)] {
                if let Some(index) = sample.labels.iter().position(|(name, _)| name == key) {
                    let mut exported = format!("exported_{key}");
                    while sample.labels.iter().any(|(name, _)| name == &exported) {
                        exported = format!("exported_{exported}");
                    }
                    sample.labels[index].0 = exported;
                }
                sample.labels.push((key.into(), value.into()));
            }
            sample
        })
        .collect()
}

pub fn to_agent_samples(samples: &[ExpositionSample], now_ms: i64) -> Vec<Sample> {
    samples
        .iter()
        // Kestrel's metric stores accept finite values. One missing exporter
        // observation must not discard the other metrics in the scrape.
        .filter(|sample| sample.value.is_finite())
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
    let samples: Vec<&Sample> = samples
        .iter()
        .filter(|sample| {
            valid_name(&sample.name)
                && sample.value.is_finite()
                && sample.labels.iter().enumerate().all(|(index, (key, _))| {
                    valid_name(key)
                        && !key.contains(':')
                        && !sample.labels[..index]
                            .iter()
                            .any(|(previous, _)| previous == key)
                })
        })
        .collect();
    let mut types: BTreeMap<&str, &str> = BTreeMap::new();
    for sample in &samples {
        let kind = if sample.name.ends_with("_total") {
            "counter"
        } else {
            "gauge"
        };
        types.entry(sample.name.as_str()).or_insert(kind);
    }
    let mut out = String::new();
    for (name, kind) in types {
        out.push_str("# HELP ");
        out.push_str(name);
        out.push_str(" Latest observed value for ");
        out.push_str(&name.replace('\\', "\\\\").replace('\n', "\\n"));
        out.push_str(".\n");
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
    fn prom_scrape_handles_escaped_labels_and_rejects_ambiguous_sets() {
        let parsed = parse_exposition(r#"metric{path="a\" b", method="GET"} 1"#).unwrap();
        assert_eq!(parsed[0].labels[0].1, "a\" b");
        for bad in [
            r#"metric{a="x" a="y"} 1"#,
            r#"metric{a="x",a="y"} 1"#,
            r#"metric{bad:key="x"} 1"#,
            r#"metric{a="\t"} 1"#,
        ] {
            assert!(parse_exposition(bad).is_err(), "{bad}");
        }
        let parsed = parse_exposition("metric NaN\nother +Inf\nvalid 3\n").unwrap();
        assert_eq!(to_agent_samples(&parsed, 1).len(), 1);
        let parsed = relabel(
            parse_exposition(r#"metric{job="spoof",instance="elsewhere"} 1"#).unwrap(),
            "node",
            "host",
        );
        assert!(parsed[0].labels.contains(&("job".into(), "node".into())));
        assert!(parsed[0]
            .labels
            .contains(&("exported_job".into(), "spoof".into())));
    }

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

    #[test]
    fn prom_encode_declares_help_and_type_once_for_each_metric_family() {
        let samples = (0..2)
            .map(|cpu| Sample {
                name: "kestrel_cpu_usage_ratio".into(),
                labels: vec![("cpu".into(), cpu.to_string())],
                value: 0.5,
                timestamp_ms: 123,
            })
            .collect::<Vec<_>>();
        let text = encode_exposition(&samples);
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("# HELP kestrel_cpu_usage_ratio "))
                .count(),
            1
        );
        assert_eq!(
            text.lines()
                .filter(|line| *line == "# TYPE kestrel_cpu_usage_ratio gauge")
                .count(),
            1
        );
        assert_eq!(
            text.lines().filter(|line| !line.starts_with('#')).count(),
            2
        );
        validate_exposition(&text).unwrap();
        assert_eq!(parse_exposition(&text).unwrap().len(), 2);
    }
}
