//! HTTP and Prometheus schedules for hosts that do not have an agent.

use crate::{api::ApiState, LabelledSample};
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

type Error = Box<dyn std::error::Error + Send + Sync>;

const ITEMS_SQL: &str = r#"
WITH RECURSIVE linked(tenant_id,host_id,template_id,depth,path) AS (
  SELECT tenant_id,host_id,template_id,0,ARRAY[template_id] FROM template_links
  UNION ALL
  SELECT l.tenant_id,l.host_id,p.parent_id,l.depth+1,l.path||p.parent_id FROM template_parents p
  JOIN linked l ON p.tenant_id=l.tenant_id AND p.template_id=l.template_id
  WHERE NOT p.parent_id=ANY(l.path)
), ranks AS (SELECT tenant_id,host_id,template_id,MAX(depth) AS depth FROM linked GROUP BY tenant_id,host_id,template_id)
SELECT h.tenant_id,h.id AS poll_host,h.name,i.key,i.kind,i.interval_s,i.params FROM hosts h
JOIN items i ON i.tenant_id=h.tenant_id
LEFT JOIN ranks l ON l.tenant_id=h.tenant_id AND l.host_id=h.id AND l.template_id=i.template_id
WHERE (i.host_id=h.id OR l.template_id IS NOT NULL)
AND NOT EXISTS(SELECT 1 FROM agents a WHERE a.tenant_id=h.tenant_id AND a.host_id=h.id AND a.revoked_at IS NULL)
ORDER BY h.id,i.key,(i.host_id IS NOT NULL),COALESCE(l.depth,-1) DESC,i.created_at,i.id
"#;

struct Job {
    tenant: Uuid,
    host: Uuid,
    host_name: String,
    key: String,
    kind: String,
    interval: Duration,
    params: Value,
}

pub(crate) fn spawn(state: ApiState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(db) = &state.db else {
            return;
        };
        let permits = Arc::new(Semaphore::new(256));
        let mut tasks = JoinSet::new();
        let mut active =
            BTreeMap::<(Uuid, Uuid, String), (String, tokio::task::AbortHandle)>::new();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let jobs = match load(db).await {
                Ok(jobs) => jobs,
                Err(err) => {
                    tracing::warn!(error=%err,"HTTP poller configuration reload failed");
                    continue;
                }
            };
            active.retain(|key, (_, task)| {
                if jobs
                    .iter()
                    .any(|job| &(job.tenant, job.host, job.key.clone()) == key)
                {
                    true
                } else {
                    task.abort();
                    false
                }
            });
            for job in jobs {
                let key = (job.tenant, job.host, job.key.clone());
                let signature = format!(
                    "{}:{}:{:?}:{}",
                    job.host_name, job.kind, job.interval, job.params
                );
                if active
                    .get(&key)
                    .is_some_and(|(old, task)| old == &signature && !task.is_finished())
                {
                    continue;
                }
                if let Some((_, task)) = active.remove(&key) {
                    task.abort();
                }
                let store = state.store.clone();
                let permits = permits.clone();
                let task=tasks.spawn(async move {
                    let mut interval=tokio::time::interval(job.interval);interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        let Ok(_permit)=permits.acquire().await else{return;};
                        match collect(&job).await {
                            Ok(samples)=>{if let Err(err)=store.write(samples).await {tracing::warn!(host=%job.host,error=%err,"HTTP poller could not store samples");}},
                            Err(_)=>tracing::warn!(host=%job.host,item=%job.key,"HTTP or Prometheus poll failed"),
                        }
                    }
                });
                active.insert(key, (signature, task));
            }
            while tasks.try_join_next().is_some() {}
        }
    })
}

async fn load(db: &crate::db::Db) -> Result<Vec<Job>, Error> {
    let rows = sqlx::query(ITEMS_SQL).fetch_all(&db.pool).await?;
    let mut jobs = BTreeMap::new();
    for row in rows {
        let job = Job {
            tenant: row.try_get("tenant_id")?,
            host: row.try_get("poll_host")?,
            host_name: row.try_get("name")?,
            key: row.try_get("key")?,
            kind: row.try_get("kind")?,
            interval: Duration::from_secs(row.try_get::<i32, _>("interval_s")?.max(1) as u64),
            params: row.try_get("params")?,
        };
        jobs.insert((job.tenant, job.host, job.key.clone()), job);
    }
    Ok(jobs
        .into_values()
        .filter(|job| matches!(job.kind.as_str(), "http" | "prometheus" | "prom_scrape"))
        .collect())
}

async fn collect(job: &Job) -> Result<Vec<LabelledSample>, Error> {
    let url = job.params["url"].as_str().ok_or("missing HTTP URL")?;
    let timeout = Duration::from_secs(job.params["timeout_s"].as_u64().unwrap_or(10).clamp(1, 300));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let mut samples = if job.kind == "http" {
        let check = kestrel_checks::HttpCheck {
            id: job.key.clone(),
            url: url.into(),
            timeout,
            body_regex: job.params["body_regex"].as_str().map(str::to_string),
        };
        let mut samples = kestrel_checks::run_http_check(&check, now).await.samples;
        if let Some(name) = job.params["job"].as_str() {
            for sample in &mut samples {
                sample.labels.push(("job".into(), name.into()));
            }
        }
        samples
    } else {
        kestrel_checks::scrape_prometheus(
            url,
            job.params["job"].as_str().unwrap_or(&job.key),
            job.params["instance"].as_str().unwrap_or(""),
            timeout,
            now,
        )
        .await?
    };
    Ok(samples
        .drain(..)
        .map(|sample| {
            let mut labels: Vec<_> = sample
                .labels
                .into_iter()
                .filter(|(name, _)| {
                    !matches!(name.as_str(), "tenant" | "host" | "host_id" | "agent")
                })
                .collect();
            labels.extend([
                ("tenant".into(), job.tenant.to_string()),
                ("host".into(), job.host_name.clone()),
                ("host_id".into(), job.host.to_string()),
            ]);
            LabelledSample {
                name: sample.name,
                labels,
                value: sample.value,
                timestamp_ms: sample.timestamp_ms,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    #[tokio::test]
    async fn server_polls_http_and_exporters_with_host_tenant_labels() {
        let server = MockServer::start().await;
        Mock::given(path("/failed"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(path("/metrics"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("node_cpu_seconds_total{tenant=\"spoof\"} 123\n"),
            )
            .mount(&server)
            .await;
        let mut job = Job {
            tenant: Uuid::new_v4(),
            host: Uuid::new_v4(),
            host_name: "web".into(),
            key: "site".into(),
            kind: "http".into(),
            interval: Duration::from_secs(30),
            params: serde_json::json!({"url":format!("{}/failed",server.uri())}),
        };
        let samples = collect(&job).await.unwrap();
        assert!(samples
            .iter()
            .any(|s| s.name == "kestrel_http_up" && s.value == 0.0));
        job.kind = "prometheus".into();
        job.params = serde_json::json!({"url":format!("{}/metrics",server.uri()),"job":"node"});
        let samples = collect(&job).await.unwrap();
        assert_eq!(samples[0].value, 123.0);
        assert_eq!(
            samples[0]
                .labels
                .iter()
                .filter(|(name, _)| name == "tenant")
                .count(),
            1
        );
        assert!(samples[0]
            .labels
            .contains(&("tenant".into(), job.tenant.to_string())));
    }
}
