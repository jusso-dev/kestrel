//! OTLP metrics over HTTP. Resource attributes become labels, with a cap.

use kestrel_proto::otel::{
    metric::Data, number_data_point::Value as NumberValue, ExportMetricsServiceRequest, KeyValue,
};
use prost::Message;
use serde_json::Value as Json;

pub const MAX_LABELS: usize = 30;

#[derive(Debug, Clone, PartialEq)]
pub struct OtlpSample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
    pub timestamp_ms: i64,
}

pub fn samples_from_protobuf(bytes: &[u8], drop: &[&str]) -> Result<Vec<OtlpSample>, String> {
    let request = ExportMetricsServiceRequest::decode(bytes).map_err(|err| err.to_string())?;
    Ok(normalise_samples(samples_from_request(&request, drop)))
}

pub fn samples_from_json(body: &str, drop: &[&str]) -> Result<Vec<OtlpSample>, String> {
    let value: Json = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let mut samples = Vec::new();
    let resources = value
        .get("resourceMetrics")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    for resource in resources {
        let mut labels = attributes_json(resource.get("resource"), drop);
        let scopes = resource
            .get("scopeMetrics")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        for scope in scopes {
            let metrics = scope
                .get("metrics")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default();
            for metric in metrics {
                let name = metric.get("name").and_then(Json::as_str).unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                if let Some(gauge) = metric.get("gauge").or_else(|| metric.get("sum")) {
                    for point in gauge
                        .get("dataPoints")
                        .and_then(Json::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let mut point_labels = labels.clone();
                        point_labels.extend(attributes_json(Some(point), drop));
                        point_labels = merge_labels(point_labels);
                        if point_labels.len() > MAX_LABELS - 1 {
                            continue;
                        }
                        let value = point
                            .get("asDouble")
                            .and_then(number)
                            .or_else(|| point.get("asInt").and_then(number))
                            .unwrap_or(0.0);
                        samples.push(OtlpSample {
                            name: name.to_string(),
                            labels: point_labels,
                            value,
                            timestamp_ms: unix_nano_ms(point.get("timeUnixNano")),
                        });
                    }
                }
                if let Some(histogram) = metric.get("histogram") {
                    for point in histogram
                        .get("dataPoints")
                        .and_then(Json::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let mut point_labels = labels.clone();
                        point_labels.extend(attributes_json(Some(point), drop));
                        point_labels = merge_labels(point_labels);
                        if point_labels.len() > MAX_LABELS - 2 {
                            continue;
                        }
                        let ts = unix_nano_ms(point.get("timeUnixNano"));
                        if let Some(sum) = point.get("sum").and_then(number) {
                            samples.push(OtlpSample {
                                name: format!("{name}_sum"),
                                labels: point_labels.clone(),
                                value: sum,
                                timestamp_ms: ts,
                            });
                        }
                        if let Some(count) = point.get("count").and_then(number) {
                            samples.push(OtlpSample {
                                name: format!("{name}_count"),
                                labels: point_labels.clone(),
                                value: count,
                                timestamp_ms: ts,
                            });
                        }
                        let bounds = point
                            .get("explicitBounds")
                            .and_then(Json::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let counts = point
                            .get("bucketCounts")
                            .and_then(Json::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let mut cumulative = 0.0;
                        for (index, bound) in bounds.iter().enumerate() {
                            cumulative += counts.get(index).and_then(number).unwrap_or(0.0);
                            let mut bucket_labels = point_labels.clone();
                            bucket_labels.push(("le".to_string(), json_number(bound)));
                            samples.push(OtlpSample {
                                name: format!("{name}_bucket"),
                                labels: bucket_labels,
                                value: cumulative,
                                timestamp_ms: ts,
                            });
                        }
                        let mut bucket_labels = point_labels.clone();
                        bucket_labels.push(("le".to_string(), "+Inf".to_string()));
                        samples.push(OtlpSample {
                            name: format!("{name}_bucket"),
                            labels: bucket_labels,
                            value: point
                                .get("count")
                                .and_then(number)
                                .unwrap_or_else(|| counts.iter().filter_map(number).sum()),
                            timestamp_ms: ts,
                        });
                    }
                }
            }
        }
        let _ = &mut labels;
    }
    Ok(normalise_samples(samples))
}

fn samples_from_request(request: &ExportMetricsServiceRequest, drop: &[&str]) -> Vec<OtlpSample> {
    let mut samples = Vec::new();
    for resource in &request.resource_metrics {
        let resource_labels = resource
            .resource
            .as_ref()
            .map(|resource| attributes(&resource.attributes, drop))
            .unwrap_or_default();
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                match &metric.data {
                    Some(Data::Gauge(gauge)) => {
                        push_numbers(
                            &mut samples,
                            &metric.name,
                            &resource_labels,
                            &gauge.data_points,
                            drop,
                        );
                    }
                    Some(Data::Sum(sum)) => {
                        push_numbers(
                            &mut samples,
                            &metric.name,
                            &resource_labels,
                            &sum.data_points,
                            drop,
                        );
                    }
                    Some(Data::Histogram(histogram)) => {
                        for point in &histogram.data_points {
                            let mut labels = resource_labels.clone();
                            labels.extend(attributes(&point.attributes, drop));
                            labels = merge_labels(labels);
                            if labels.len() > MAX_LABELS - 2 {
                                continue;
                            }
                            let ts = (point.time_unix_nano / 1_000_000) as i64;
                            if let Some(sum) = point.sum {
                                samples.push(OtlpSample {
                                    name: format!("{}_sum", metric.name),
                                    labels: labels.clone(),
                                    value: sum,
                                    timestamp_ms: ts,
                                });
                            }
                            samples.push(OtlpSample {
                                name: format!("{}_count", metric.name),
                                labels: labels.clone(),
                                value: point.count as f64,
                                timestamp_ms: ts,
                            });
                            let mut cumulative = 0u64;
                            for (index, bound) in point.explicit_bounds.iter().enumerate() {
                                cumulative = cumulative.saturating_add(
                                    point.bucket_counts.get(index).copied().unwrap_or(0),
                                );
                                let mut bucket = labels.clone();
                                bucket.push(("le".to_string(), bound.to_string()));
                                samples.push(OtlpSample {
                                    name: format!("{}_bucket", metric.name),
                                    labels: bucket,
                                    value: cumulative as f64,
                                    timestamp_ms: ts,
                                });
                            }
                            let mut bucket = labels.clone();
                            bucket.push(("le".to_string(), "+Inf".to_string()));
                            samples.push(OtlpSample {
                                name: format!("{}_bucket", metric.name),
                                labels: bucket,
                                value: point.count as f64,
                                timestamp_ms: ts,
                            });
                        }
                    }
                    None => {}
                }
            }
        }
    }
    samples
}

fn push_numbers(
    samples: &mut Vec<OtlpSample>,
    name: &str,
    resource_labels: &[(String, String)],
    points: &[kestrel_proto::otel::NumberDataPoint],
    drop: &[&str],
) {
    for point in points {
        let mut labels = resource_labels.to_vec();
        labels.extend(attributes(&point.attributes, drop));
        labels = merge_labels(labels);
        if labels.len() > MAX_LABELS - 1 {
            continue;
        }
        let value = match point.value {
            Some(NumberValue::AsDouble(value)) => value,
            Some(NumberValue::AsInt(value)) => value as f64,
            None => 0.0,
        };
        samples.push(OtlpSample {
            name: name.to_string(),
            labels,
            value,
            timestamp_ms: (point.time_unix_nano / 1_000_000) as i64,
        });
    }
}

fn attributes(values: &[KeyValue], drop: &[&str]) -> Vec<(String, String)> {
    let mut labels = Vec::new();
    for item in values {
        if drop.contains(&item.key.as_str()) {
            continue;
        }
        let Some(value) = item.value.as_ref().and_then(|value| value.value.as_ref()) else {
            continue;
        };
        let text = match value {
            kestrel_proto::otel::any_value::Value::StringValue(value) => value.clone(),
            kestrel_proto::otel::any_value::Value::BoolValue(value) => value.to_string(),
            kestrel_proto::otel::any_value::Value::IntValue(value) => value.to_string(),
            kestrel_proto::otel::any_value::Value::DoubleValue(value) => value.to_string(),
        };
        let key = match item.key.as_str() {
            "service.name" => "job".to_string(),
            "host.name" => "host".to_string(),
            other => other.to_string(),
        };
        labels.push((key, text));
    }
    labels
}

fn attributes_json(value: Option<&Json>, drop: &[&str]) -> Vec<(String, String)> {
    let Some(list) = value
        .and_then(|value| value.get("attributes").or(Some(value)))
        .and_then(|value| value.get("attributes").or(Some(value)))
        .and_then(Json::as_array)
        .or_else(|| {
            value
                .and_then(|value| value.get("attributes"))
                .and_then(Json::as_array)
        })
    else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    for item in list {
        let Some(key) = item.get("key").and_then(Json::as_str) else {
            continue;
        };
        if drop.contains(&key) {
            continue;
        }
        let raw = item
            .pointer("/value/stringValue")
            .and_then(Json::as_str)
            .map(str::to_string)
            .or_else(|| {
                item.pointer("/value/intValue")
                    .and_then(Json::as_str)
                    .map(str::to_string)
            })
            .or_else(|| {
                item.pointer("/value/doubleValue")
                    .and_then(Json::as_f64)
                    .map(|value| value.to_string())
            })
            .or_else(|| {
                item.pointer("/value/intValue")
                    .and_then(number)
                    .map(|value| value.to_string())
            })
            .or_else(|| {
                item.pointer("/value/boolValue")
                    .and_then(Json::as_bool)
                    .map(|value| value.to_string())
            });
        let Some(raw) = raw else {
            continue;
        };
        let key = match key {
            "service.name" => "job",
            "host.name" => "host",
            other => other,
        };
        labels.push((key.to_string(), raw));
    }
    labels
}

fn unix_nano_ms(value: Option<&Json>) -> i64 {
    if let Some(text) = value.and_then(Json::as_str) {
        return text.parse::<i64>().unwrap_or(0) / 1_000_000;
    }
    value.and_then(Json::as_i64).unwrap_or(0) / 1_000_000
}

fn json_number(value: &Json) -> String {
    value
        .as_f64()
        .map(|number| number.to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn normalise_samples(samples: Vec<OtlpSample>) -> Vec<OtlpSample> {
    samples
        .into_iter()
        .filter_map(|mut sample| {
            sample.name = sample
                .name
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':') {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect();
            if sample.name.is_empty() {
                return None;
            }
            if sample.name.starts_with(|ch: char| ch.is_ascii_digit()) {
                sample.name.insert(0, '_');
            }
            sample.labels = merge_labels(sample.labels);
            if sample.labels.len() >= MAX_LABELS {
                return None;
            }
            Some(sample)
        })
        .collect()
}

fn number(value: &Json) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn merge_labels(labels: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut unique = std::collections::BTreeMap::new();
    for (name, value) in labels {
        let name = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        if name.is_empty()
            || name.starts_with(|ch: char| ch.is_ascii_digit())
            || matches!(name.as_str(), "tenant" | "__name__")
        {
            continue;
        }
        unique.insert(name, value);
    }
    unique.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otlp_json_string_numbers_histogram_infinity_and_attribute_overrides() {
        let body=serde_json::json!({"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"old"}},{"key":"http.route","value":{"stringValue":"/checkout"}}]},"scopeMetrics":[{"metrics":[{"name":"duration","histogram":{"dataPoints":[{"count":"3","sum":4.5,"bucketCounts":["1","1","1"],"explicitBounds":[1.0,2.0],"timeUnixNano":"1700000000000000000","attributes":[{"key":"service.name","value":{"stringValue":"new"}}]}]}},{"name":"requests","sum":{"dataPoints":[{"asInt":"17","timeUnixNano":"1700000000000000000"}]}}]}]}]}).to_string();
        let samples = samples_from_json(&body, &[]).unwrap();
        assert!(samples
            .iter()
            .any(|sample| sample.name == "requests" && sample.value == 17.0));
        let bucket = samples
            .iter()
            .find(|sample| {
                sample
                    .labels
                    .iter()
                    .any(|(name, value)| name == "le" && value == "+Inf")
            })
            .unwrap();
        assert_eq!(bucket.value, 3.0);
        assert_eq!(
            bucket
                .labels
                .iter()
                .filter(|(name, _)| name == "job")
                .count(),
            1
        );
        assert!(bucket
            .labels
            .iter()
            .any(|(name, value)| name == "job" && value == "new"));
        assert!(bucket.labels.iter().any(|(name, _)| name == "http_route"));
    }

    #[test]
    fn otlp_json_maps_service_name_and_enforces_cardinality() {
        let body = r#"{
          "resourceMetrics": [{
            "resource": {"attributes": [
              {"key": "service.name", "value": {"stringValue": "checkout"}},
              {"key": "host.name", "value": {"stringValue": "web-1"}},
              {"key": "user_id", "value": {"stringValue": "secret"}}
            ]},
            "scopeMetrics": [{
              "metrics": [{
                "name": "requests",
                "gauge": {"dataPoints": [{"asDouble": 3.0, "timeUnixNano": "1700000000000000000", "attributes": []}]}
              }]
            }]
          }]
        }"#;
        let samples = samples_from_json(body, &["user_id"]).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].name, "requests");
        assert!(samples[0]
            .labels
            .iter()
            .any(|(k, v)| k == "job" && v == "checkout"));
        assert!(samples[0]
            .labels
            .iter()
            .any(|(k, v)| k == "host" && v == "web-1"));
        assert!(!samples[0].labels.iter().any(|(k, _)| k == "user_id"));
        let mut wide = String::from(r#"{"resourceMetrics":[{"resource":{"attributes":["#);
        for index in 0..40 {
            if index > 0 {
                wide.push(',');
            }
            wide.push_str(&format!(
                r#"{{"key":"a{index}","value":{{"stringValue":"v"}}}}"#
            ));
        }
        wide.push_str(r#"]},"scopeMetrics":[{"metrics":[{"name":"wide","gauge":{"dataPoints":[{"asDouble":1,"timeUnixNano":"1","attributes":[]}]}}]}]}]}"#);
        let samples = samples_from_json(&wide, &[]).unwrap();
        assert!(samples.is_empty(), "more than 30 labels must be dropped");
    }
}
