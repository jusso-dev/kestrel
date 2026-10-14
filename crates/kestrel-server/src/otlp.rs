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
    Ok(samples_from_request(&request, drop))
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
                        if point_labels.len() > MAX_LABELS {
                            continue;
                        }
                        let value = point
                            .get("asDouble")
                            .and_then(Json::as_f64)
                            .or_else(|| point.get("asInt").and_then(Json::as_f64))
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
                        if point_labels.len() > MAX_LABELS {
                            continue;
                        }
                        let ts = unix_nano_ms(point.get("timeUnixNano"));
                        if let Some(sum) = point.get("sum").and_then(Json::as_f64) {
                            samples.push(OtlpSample {
                                name: format!("{name}_sum"),
                                labels: point_labels.clone(),
                                value: sum,
                                timestamp_ms: ts,
                            });
                        }
                        if let Some(count) = point.get("count").and_then(Json::as_f64) {
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
                            cumulative += counts.get(index).and_then(Json::as_f64).unwrap_or(0.0);
                            let mut bucket_labels = point_labels.clone();
                            bucket_labels.push(("le".to_string(), json_number(bound)));
                            samples.push(OtlpSample {
                                name: format!("{name}_bucket"),
                                labels: bucket_labels,
                                value: cumulative,
                                timestamp_ms: ts,
                            });
                        }
                    }
                }
            }
        }
        let _ = &mut labels;
    }
    Ok(samples)
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
                            if labels.len() > MAX_LABELS {
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
                                cumulative += point.bucket_counts.get(index).copied().unwrap_or(0);
                                let mut bucket = labels.clone();
                                bucket.push(("le".to_string(), bound.to_string()));
                                samples.push(OtlpSample {
                                    name: format!("{}_bucket", metric.name),
                                    labels: bucket,
                                    value: cumulative as f64,
                                    timestamp_ms: ts,
                                });
                            }
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
        if labels.len() > MAX_LABELS {
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

#[cfg(test)]
mod tests {
    use super::*;

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
