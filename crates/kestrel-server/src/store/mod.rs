//! Metric storage. Enrolment records live in [`enrolment`].
//!
//! [`MetricStore`] is the time-series boundary. [`VictoriaStore`] speaks
//! Prometheus remote write and PromQL. Tests use [`MemoryStore`] so they do
//! not need a running VictoriaMetrics.

mod enrolment;
mod memory;
mod victoria;

pub use enrolment::*;
pub use memory::MemoryStore;
pub use victoria::VictoriaStore;

use async_trait::async_trait;

/// One sample plus the labels the server attaches (`tenant`, `host`, `agent`).
#[derive(Debug, Clone, PartialEq)]
pub struct LabelledSample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
    pub timestamp_ms: i64,
}

/// One series returned by an instant or range query.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub labels: Vec<(String, String)>,
    pub points: Vec<(i64, f64)>,
}

/// Time-series read and write. `at`, `start` and `end` are unix seconds.
#[async_trait]
pub trait MetricStore: Send + Sync {
    async fn write(&self, samples: Vec<LabelledSample>) -> Result<(), crate::ServerError>;
    async fn query(&self, promql: &str, at: i64) -> Result<Vec<Series>, crate::ServerError>;
    async fn query_range(
        &self,
        promql: &str,
        start: i64,
        end: i64,
        step_s: u32,
    ) -> Result<Vec<Series>, crate::ServerError>;
}
