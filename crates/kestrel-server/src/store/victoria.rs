//! VictoriaMetrics client: Prometheus remote write and PromQL.

use super::{LabelledSample, MetricStore, Series};
use async_trait::async_trait;
use kestrel_proto::remote::{Label, Sample, TimeSeries, WriteRequest};
use prost::Message;
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct VictoriaStore {
    client: Client,
    base: String,
}

impl VictoriaStore {
    pub fn new(base: &str) -> Result<Self, crate::ServerError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| crate::ServerError::new(format!("victoria client: {err}")))?;
        let base = base.trim_end_matches('/').to_string();
        Ok(Self { client, base })
    }

    /// Snappy-compressed remote-write body for `samples`.
    pub fn encode_write(samples: &[LabelledSample]) -> Result<Vec<u8>, crate::ServerError> {
        let request = write_request(samples);
        let raw = request.encode_to_vec();
        snap::raw::Encoder::new()
            .compress_vec(&raw)
            .map_err(|err| crate::ServerError::new(format!("snappy: {err}")))
    }
}

#[async_trait]
impl MetricStore for VictoriaStore {
    async fn write(&self, samples: Vec<LabelledSample>) -> Result<(), crate::ServerError> {
        if samples.is_empty() {
            return Ok(());
        }
        let body = Self::encode_write(&samples)?;
        let url = format!("{}/api/v1/write", self.base);
        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/x-protobuf")
            .header(CONTENT_ENCODING, "snappy")
            .header("X-Prometheus-Remote-Write-Version", "0.1.0")
            .body(body)
            .send()
            .await
            .map_err(|err| crate::ServerError::new(format!("victoria write: {err}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(crate::ServerError::new(format!(
                "victoria write failed: {status} {}",
                trim_body(&text)
            )));
        }
        Ok(())
    }

    async fn query(&self, promql: &str, at: i64) -> Result<Vec<Series>, crate::ServerError> {
        let url = format!("{}/api/v1/query", self.base);
        let response = self
            .client
            .get(url)
            // VictoriaMetrics otherwise shifts recent instant-query timestamps
            // backwards by search.latencyOffset (30 seconds by default).
            .query(&[
                ("query", promql),
                ("time", &at.to_string()),
                ("nocache", "1"),
            ])
            .send()
            .await
            .map_err(|err| crate::ServerError::new(format!("victoria query: {err}")))?;
        parse_response(response).await
    }

    async fn query_range(
        &self,
        promql: &str,
        start: i64,
        end: i64,
        step_s: u32,
    ) -> Result<Vec<Series>, crate::ServerError> {
        let url = format!("{}/api/v1/query_range", self.base);
        let step = format!("{step_s}s");
        let response = self
            .client
            .get(url)
            .query(&[
                ("query", promql),
                ("start", &start.to_string()),
                ("end", &end.to_string()),
                ("step", &step),
            ])
            .send()
            .await
            .map_err(|err| crate::ServerError::new(format!("victoria query_range: {err}")))?;
        parse_response(response).await
    }
}

fn write_request(samples: &[LabelledSample]) -> WriteRequest {
    let mut grouped: BTreeMap<Vec<(String, String)>, Vec<Sample>> = BTreeMap::new();
    for sample in samples {
        let mut labels = vec![("__name__".to_string(), sample.name.clone())];
        labels.extend(sample.labels.iter().cloned());
        labels.sort();
        grouped.entry(labels).or_default().push(Sample {
            value: sample.value,
            timestamp: sample.timestamp_ms,
        });
    }
    WriteRequest {
        timeseries: grouped
            .into_iter()
            .map(|(labels, samples)| TimeSeries {
                labels: labels
                    .into_iter()
                    .map(|(name, value)| Label { name, value })
                    .collect(),
                samples,
            })
            .collect(),
    }
}

async fn parse_response(response: reqwest::Response) -> Result<Vec<Series>, crate::ServerError> {
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(crate::ServerError::new(format!(
            "victoria query failed: {status} {}",
            trim_body(&text)
        )));
    }
    let body = response
        .text()
        .await
        .map_err(|err| crate::ServerError::new(format!("victoria query: {err}")))?;
    parse_query_json(&body)
}

pub fn parse_query_json(body: &str) -> Result<Vec<Series>, crate::ServerError> {
    let parsed: QueryEnvelope = serde_json::from_str(body)
        .map_err(|err| crate::ServerError::new(format!("victoria json: {err}")))?;
    if parsed.status != "success" {
        return Err(crate::ServerError::new(format!(
            "victoria status {}",
            parsed.status
        )));
    }
    let mut series = Vec::new();
    for item in parsed.data.result {
        let labels = item.metric.into_iter().collect();
        let mut points = Vec::new();
        if let Some(value) = item.value {
            if let Some(point) = parse_point(&value) {
                points.push(point);
            }
        }
        if let Some(values) = item.values {
            for value in values {
                if let Some(point) = parse_point(&value) {
                    points.push(point);
                }
            }
        }
        series.push(Series { labels, points });
    }
    Ok(series)
}

fn parse_point(value: &[Value]) -> Option<(i64, f64)> {
    let ts = value.first()?.as_f64()?.round() as i64;
    let raw = value.get(1)?.as_str()?;
    let sample: f64 = raw.parse().ok()?;
    Some((ts, sample))
}

fn trim_body(text: &str) -> String {
    let mut trimmed = text.chars().take(180).collect::<String>();
    if text.chars().count() > 180 {
        trimmed.push('…');
    }
    trimmed
}

#[derive(Debug, Deserialize)]
struct QueryEnvelope {
    status: String,
    data: QueryData,
}

#[derive(Debug, Deserialize)]
struct QueryData {
    result: Vec<QuerySeries>,
}

#[derive(Debug, Deserialize)]
struct QuerySeries {
    metric: BTreeMap<String, String>,
    value: Option<Vec<Value>>,
    values: Option<Vec<Vec<Value>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_write_round_trip_includes_tenant_and_host() {
        let samples = vec![LabelledSample {
            name: "kestrel_memory_used_bytes".to_string(),
            labels: vec![
                ("tenant".to_string(), "default".to_string()),
                ("host".to_string(), "web-1".to_string()),
                ("agent".to_string(), "agent-1".to_string()),
            ],
            value: 1024.0,
            timestamp_ms: 1_700_000_000_000,
        }];
        let compressed = VictoriaStore::encode_write(&samples).unwrap();
        let raw = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let request = WriteRequest::decode(raw.as_slice()).unwrap();
        assert_eq!(request.timeseries.len(), 1);
        let series = &request.timeseries[0];
        let names: Vec<&str> = series
            .labels
            .iter()
            .map(|label| label.name.as_str())
            .collect();
        assert!(names.contains(&"__name__"));
        assert!(names.contains(&"tenant"));
        assert!(names.contains(&"host"));
        assert!(names.contains(&"agent"));
        assert_eq!(series.samples[0].value, 1024.0);
        assert_eq!(series.samples[0].timestamp, 1_700_000_000_000);
    }

    #[test]
    fn query_json_parses_instant_and_range() {
        let instant = r#"{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","host":"web"},"value":[1700000000,"1"]}]}}"#;
        let series = parse_query_json(instant).unwrap();
        assert_eq!(series[0].points, vec![(1_700_000_000, 1.0)]);
        let range = r#"{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"up"},"values":[[1700000000,"1"],[1700000030,"0"]]}]}}"#;
        let series = parse_query_json(range).unwrap();
        assert_eq!(series[0].points.len(), 2);
    }

    #[tokio::test]
    async fn victoria_store_posts_remote_write_and_queries() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/write"))
            .and(wiremock::matchers::header("content-encoding", "snappy"))
            .respond_with(wiremock::ResponseTemplate::new(204))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/query"))
            .and(wiremock::matchers::query_param("nocache", "1"))
            .and(wiremock::matchers::query_param("time", "1700000000"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                r#"{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"kestrel_memory_used_bytes","tenant":"default","host":"web-1"},"value":[1700000000,"1024"]}]}}"#,
            ))
            .mount(&server)
            .await;
        let store = VictoriaStore::new(&server.uri()).unwrap();
        store
            .write(vec![LabelledSample {
                name: "kestrel_memory_used_bytes".to_string(),
                labels: vec![
                    ("tenant".to_string(), "default".to_string()),
                    ("host".to_string(), "web-1".to_string()),
                ],
                value: 1024.0,
                timestamp_ms: 1_700_000_000_000,
            }])
            .await
            .unwrap();
        let series = store
            .query("kestrel_memory_used_bytes", 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(series[0].points[0].1, 1024.0);
        assert!(series[0]
            .labels
            .iter()
            .any(|(name, value)| name == "tenant" && value == "default"));
        assert!(series[0]
            .labels
            .iter()
            .any(|(name, value)| name == "host" && value == "web-1"));
    }
}
