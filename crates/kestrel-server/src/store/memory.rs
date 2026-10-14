//! In-memory [`super::MetricStore`] for tests and for running without VictoriaMetrics.

use super::{LabelledSample, MetricStore, Series};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct MemoryStore {
    samples: Mutex<Vec<LabelledSample>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.samples
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl MetricStore for MemoryStore {
    async fn write(&self, samples: Vec<LabelledSample>) -> Result<(), crate::ServerError> {
        self.samples
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .extend(samples);
        Ok(())
    }

    async fn query(&self, promql: &str, at: i64) -> Result<Vec<Series>, crate::ServerError> {
        let samples = self
            .samples
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        Ok(evaluate(&samples, promql, at, at, 0, true))
    }

    async fn query_range(
        &self,
        promql: &str,
        start: i64,
        end: i64,
        step_s: u32,
    ) -> Result<Vec<Series>, crate::ServerError> {
        let samples = self
            .samples
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        Ok(evaluate(&samples, promql, start, end, step_s, false))
    }
}

#[derive(Debug)]
struct Selector {
    name: String,
    matchers: Vec<Matcher>,
    op: Option<Cmp>,
    threshold: Option<f64>,
    time_minus: bool,
}

#[derive(Debug)]
struct Matcher {
    name: String,
    op: MatchOp,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchOp {
    Eq,
    Neq,
    Re,
    Nre,
}

#[derive(Debug, Clone, Copy)]
enum Cmp {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Neq,
}

fn evaluate(
    samples: &[LabelledSample],
    promql: &str,
    start: i64,
    end: i64,
    step_s: u32,
    instant: bool,
) -> Vec<Series> {
    let Some(selector) = parse_selector(promql.trim()) else {
        return Vec::new();
    };
    type Grouped = BTreeMap<Vec<(String, String)>, Vec<(i64, f64)>>;
    let mut grouped: Grouped = BTreeMap::new();
    for sample in samples {
        if sample.name != selector.name {
            continue;
        }
        if !labels_match(&sample.labels, &selector.matchers) {
            continue;
        }
        let sec = sample.timestamp_ms.div_euclid(1000);
        if instant {
            if sec > end {
                continue;
            }
        } else if !(start..=end).contains(&sec) {
            continue;
        }
        let labels = series_labels(&sample.name, &sample.labels);
        grouped.entry(labels).or_default().push((sec, sample.value));
    }
    let mut series = Vec::new();
    for (labels, mut points) in grouped {
        points.sort_by_key(|(ts, _)| *ts);
        points.dedup_by_key(|(ts, _)| *ts);
        if instant {
            let Some((ts, value)) = points.iter().rev().find(|(ts, _)| *ts <= end).copied() else {
                continue;
            };
            if !point_matches(&selector, end, value) {
                continue;
            }
            series.push(Series {
                labels,
                points: vec![(ts, value)],
            });
            continue;
        }
        let points: Vec<(i64, f64)> = if step_s == 0 {
            points
                .into_iter()
                .filter(|(_, value)| point_matches(&selector, end, *value))
                .collect()
        } else {
            let mut bucketed = Vec::new();
            let mut cursor = start;
            while cursor <= end {
                if let Some(point) = points.iter().rev().find(|(ts, _)| *ts <= cursor) {
                    if point_matches(&selector, cursor, point.1) {
                        bucketed.push(*point);
                    }
                }
                cursor = cursor.saturating_add(i64::from(step_s));
            }
            bucketed.dedup();
            bucketed
        };
        if !points.is_empty() {
            series.push(Series { labels, points });
        }
    }
    series
}

fn point_matches(selector: &Selector, at: i64, value: f64) -> bool {
    let observed = if selector.time_minus {
        let value_sec = if value.abs() > 1.0e12 {
            value / 1000.0
        } else {
            value
        };
        at as f64 - value_sec
    } else {
        value
    };
    match (selector.op, selector.threshold) {
        (Some(op), Some(threshold)) => compare(op, observed, threshold),
        _ => true,
    }
}

fn compare(op: Cmp, value: f64, threshold: f64) -> bool {
    match op {
        Cmp::Gt => value > threshold,
        Cmp::Ge => value >= threshold,
        Cmp::Lt => value < threshold,
        Cmp::Le => value <= threshold,
        Cmp::Eq => value == threshold,
        Cmp::Neq => value != threshold,
    }
}

fn series_labels(name: &str, labels: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = vec![("__name__".to_string(), name.to_string())];
    let mut rest = labels.to_vec();
    rest.sort();
    out.extend(rest);
    out
}

fn labels_match(labels: &[(String, String)], matchers: &[Matcher]) -> bool {
    matchers.iter().all(|matcher| {
        let found = labels.iter().find(|(name, _)| name == &matcher.name);
        match matcher.op {
            MatchOp::Eq => found.is_some_and(|(_, value)| value == &matcher.value),
            MatchOp::Neq => match found {
                Some((_, value)) => value != &matcher.value,
                None => true,
            },
            MatchOp::Re => found.is_some_and(|(_, value)| regex_match(&matcher.value, value)),
            MatchOp::Nre => match found {
                Some((_, value)) => !regex_match(&matcher.value, value),
                None => true,
            },
        }
    })
}

fn regex_match(pattern: &str, value: &str) -> bool {
    if pattern.len() > 200 {
        return false;
    }
    let regex = match regex::Regex::new(&format!("^(?:{pattern})$")) {
        Ok(regex) => regex,
        Err(_) => return false,
    };
    regex.is_match(value)
}

fn parse_selector(input: &str) -> Option<Selector> {
    let (time_minus, rest) = if let Some(rest) = input.strip_prefix("time()") {
        let rest = rest.trim().strip_prefix('-')?.trim();
        (true, rest)
    } else {
        (false, input)
    };
    let mut chars = rest.chars().peekable();
    let mut name = String::new();
    while let Some(ch) = chars.peek().copied() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            name.push(ch);
            chars.next();
        } else {
            break;
        }
    }
    if name.is_empty() {
        return None;
    }
    let rest: String = chars.collect();
    let rest = rest.trim();
    let (matcher_src, comparison) = if let Some(start) = rest.find('{') {
        let end = rest.find('}')?;
        if end < start {
            return None;
        }
        (Some(&rest[start + 1..end]), rest[end + 1..].trim())
    } else {
        (None, rest)
    };
    let matchers = match matcher_src {
        Some(source) => parse_matchers(source)?,
        None => Vec::new(),
    };
    let (op, threshold) = if comparison.is_empty() {
        (None, None)
    } else {
        let (op, number) = split_cmp(comparison)?;
        (Some(op), Some(number))
    };
    Some(Selector {
        name,
        matchers,
        op,
        threshold,
        time_minus,
    })
}

fn split_cmp(input: &str) -> Option<(Cmp, f64)> {
    let ops = [
        (">=", Cmp::Ge),
        ("<=", Cmp::Le),
        ("==", Cmp::Eq),
        ("!=", Cmp::Neq),
        (">", Cmp::Gt),
        ("<", Cmp::Lt),
    ];
    for (token, op) in ops {
        if let Some(rest) = input.strip_prefix(token) {
            let number: f64 = rest.trim().parse().ok()?;
            return Some((op, number));
        }
    }
    None
}

fn parse_matchers(source: &str) -> Option<Vec<Matcher>> {
    if source.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut matchers = Vec::new();
    for part in split_commas(source) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, op, value) = split_matcher(part)?;
        matchers.push(Matcher { name, op, value });
    }
    Some(matchers)
}

fn split_commas(source: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in source.chars() {
        if ch == '"' {
            quoted = !quoted;
            current.push(ch);
        } else if ch == ',' && !quoted {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn split_matcher(part: &str) -> Option<(String, MatchOp, String)> {
    let ops = [
        ("!~", MatchOp::Nre),
        ("=~", MatchOp::Re),
        ("!=", MatchOp::Neq),
        ("=", MatchOp::Eq),
    ];
    for (token, op) in ops {
        if let Some((name, value)) = part.split_once(token) {
            let value = value.trim().trim_matches('"').to_string();
            return Some((name.trim().to_string(), op, value));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
        timestamp_ms: i64,
    ) -> LabelledSample {
        LabelledSample {
            name: name.to_string(),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            value,
            timestamp_ms,
        }
    }

    #[tokio::test]
    async fn memory_store_filters_labels_and_threshold() {
        let store = MemoryStore::new();
        store
            .write(vec![
                sample(
                    "kestrel_filesystem_used_ratio",
                    &[("tenant", "a"), ("host", "web"), ("mount", "/")],
                    0.95,
                    1_700_000_000_000,
                ),
                sample(
                    "kestrel_filesystem_used_ratio",
                    &[("tenant", "b"), ("host", "web"), ("mount", "/")],
                    0.99,
                    1_700_000_000_000,
                ),
            ])
            .await
            .unwrap();
        let series = store
            .query(
                r#"kestrel_filesystem_used_ratio{tenant="a",mount="/"} > 0.9"#,
                1_700_000_000,
            )
            .await
            .unwrap();
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].points, vec![(1_700_000_000, 0.95)]);
        let none = store
            .query(
                r#"kestrel_filesystem_used_ratio{tenant="a"} > 0.99"#,
                1_700_000_000,
            )
            .await
            .unwrap();
        assert!(none.is_empty());
    }
}
