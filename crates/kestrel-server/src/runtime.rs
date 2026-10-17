//! Durable evaluation and delivery. Claims retain PostgreSQL row locks through
//! delivery; a crash rolls back the claim. Delivery is at least once.
use crate::api::{ApiState, ProblemNote};
use crate::forward::{ForwardEvent, Forwarder, WebhookForwarder, WedgetailForwarder};
use crate::maintenance::{self, Window};
use crate::notify::{self, Notifier};
use crate::rules::{self, EventKind, TriggerState};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgConnection, Row};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::task::JoinHandle;
use uuid::Uuid;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) fn spawn(state: ApiState, public_url: String) -> Vec<JoinHandle<()>> {
    if state.db.is_none() {
        return Vec::new();
    }
    let evaluator = state.clone();
    let mut tasks = vec![
        crate::poller::spawn(state.clone()),
        crate::poller::spawn_http(state.clone()),
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if let Err(err) = evaluate(&evaluator).await {
                    tracing::warn!(error=%err,"trigger evaluation failed");
                }
            }
        }),
    ];
    for forward in [false, true] {
        let state = state.clone();
        let public_url = public_url.clone();
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                for _ in 0..32 {
                    match deliver_one(&state, &public_url, forward).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(err) => {
                            tracing::warn!(error=%err,"delivery worker failed");
                            break;
                        }
                    }
                }
            }
        }));
    }
    tasks
}

async fn windows(conn: &mut PgConnection, tenant: Uuid) -> Result<Vec<Window>> {
    let rows=sqlx::query("SELECT starts_at,ends_at,rrule,host_ids,group_ids,host_group_id,suppress_problems FROM maintenances WHERE tenant_id=$1").bind(tenant).fetch_all(conn).await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let parsed: Result<Window> = (|| {
                let mut groups: Vec<Uuid> = serde_json::from_value(r.try_get("group_ids")?)?;
                if let Some(g) = r.try_get::<Option<Uuid>, _>("host_group_id")? {
                    groups.push(g);
                }
                Ok(Window {
                    starts_at: r.try_get("starts_at")?,
                    ends_at: r.try_get("ends_at")?,
                    rrule: r.try_get("rrule")?,
                    host_ids: serde_json::from_value(r.try_get("host_ids")?)?,
                    group_ids: groups,
                    suppress_problems: r.try_get("suppress_problems")?,
                })
            })();
            match parsed {
                Ok(window) => Some(window),
                Err(_) => {
                    tracing::warn!(%tenant,"ignoring malformed maintenance window");
                    None
                }
            }
        })
        .collect())
}

pub(crate) async fn enqueue_forward(
    conn: &mut PgConnection,
    tenant: Uuid,
    kind: &str,
    body: &Value,
) -> Result<()> {
    let targets=sqlx::query("SELECT id FROM media_types WHERE tenant_id=$1 AND kind IN ('wedgetail','syslog','siem_webhook')").bind(tenant).fetch_all(&mut *conn).await?;
    for target in targets {
        sqlx::query(
            "INSERT INTO forward_jobs(tenant_id,kind,status,payload) VALUES($1,$2,'pending',$3)",
        )
        .bind(tenant)
        .bind(kind)
        .bind(json!({"media_type_id":target.try_get::<Uuid,_>("id")?,"event":body}))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn evaluate(state: &ApiState) -> Result<()> {
    let db = state.db.as_ref().ok_or("database unavailable")?;
    let triggers=sqlx::query("SELECT t.*,h.name AS host_name FROM triggers t LEFT JOIN hosts h ON h.tenant_id=t.tenant_id AND h.id=t.host_id WHERE (t.enabled OR EXISTS(SELECT 1 FROM trigger_state s WHERE s.tenant_id=t.tenant_id AND s.trigger_id=t.id)) AND (t.template_id IS NULL OR t.host_id IS NOT NULL)").fetch_all(&db.pool).await?;
    for row in triggers {
        let result: Result<()> = async {
        let tenant: Uuid = row.try_get("tenant_id")?;
        let trigger_id: Uuid = row.try_get("id")?;
        let mut tx = db.pool.begin().await?;
        let locked: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
                .bind(trigger_id.to_string())
                .fetch_one(&mut *tx)
                .await?;
        if !locked {
            return Ok(());
        }
        let due:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM trigger_evaluations WHERE tenant_id=$1 AND trigger_id=$2 AND evaluated_at>now()-make_interval(secs=>$3))").bind(tenant).bind(trigger_id).bind(row.try_get::<i32,_>("interval_s")? as f64).fetch_one(&mut *tx).await?;
        if !due {
            return Ok(());
        }
        let hosts = row
            .try_get::<Option<String>, _>("host_name")?
            .map(|v| vec![v]);
        let enabled: bool = row.try_get("enabled")?;
        let now = Utc::now();
        let mut labels = BTreeMap::new();
        let mut values = BTreeMap::new();
        let firing_series = if enabled {
            let scoped=crate::promql::inject_scope(&row.try_get::<String,_>("expression")?,&tenant.to_string(),hosts.as_deref())?;
            state.store.query(&scoped,now.timestamp()).await?
        } else { Vec::new() };
        for series in firing_series {
            let value = series.points.iter().max_by_key(|(at, _)| *at)
                .map(|(_, value)| value.to_string()).unwrap_or_default();
            let pairs: Vec<_> = series
                .labels
                .into_iter()
                .filter(|(name, _)| name != "__name__")
                .collect();
            let key = rules::instance_hash(&pairs);
            values.insert(key.clone(), value);
            labels.insert(key, pairs);
        }
        let recovery: Option<String> = row.try_get("recovery_expr")?;
        let mut recovered = std::collections::BTreeSet::new();
        if let Some(expr) = recovery.as_ref().filter(|s| !s.is_empty() && enabled) {
            let expr = crate::promql::inject_scope(expr, &tenant.to_string(), hosts.as_deref())?;
            for series in state.store.query(&expr, now.timestamp()).await? {
                let pairs: Vec<_> = series
                    .labels
                    .into_iter()
                    .filter(|(name, _)| name != "__name__")
                    .collect();
                recovered.insert(rules::instance_hash(&pairs));
            }
        }
        let previous =
            sqlx::query("SELECT * FROM trigger_state WHERE tenant_id=$1 AND trigger_id=$2")
                .bind(tenant)
                .bind(trigger_id)
                .fetch_all(&mut *tx)
                .await?;
        let mut states = BTreeMap::new();
        for previous in previous {
            let value = match previous.try_get::<String, _>("state")?.as_str() {
                "pending" => TriggerState::Pending {
                    since: previous.try_get::<DateTime<Utc>, _>("since")?.timestamp(),
                },
                "problem" => TriggerState::Problem {
                    problem_id: previous.try_get("problem_id")?,
                    recover_since: previous
                        .try_get::<Option<DateTime<Utc>>, _>("recover_since")?
                        .map(|v| v.timestamp()),
                },
                _ => TriggerState::Ok,
            };
            states.insert(previous.try_get::<String, _>("instance_hash")?, value);
        }
        for key in labels.keys() {
            states.entry(key.clone()).or_insert(TriggerState::Ok);
        }
        let windows = windows(&mut tx, tenant).await?;
        let mut notes = Vec::new();
        for (key, previous) in states {
            let persisted = if let TriggerState::Problem { problem_id, .. } = &previous {
                sqlx::query("SELECT p.labels,p.trigger_value,h.name AS host_name FROM problems p LEFT JOIN hosts h ON h.tenant_id=p.tenant_id AND h.id=p.host_id WHERE p.tenant_id=$1 AND p.id=$2")
                    .bind(tenant).bind(problem_id).fetch_optional(&mut *tx).await?
            } else { None };
            let previous_labels: BTreeMap<String, String> = persisted.as_ref()
                .map(|p| p.try_get::<Value, _>("labels"))
                .transpose()?.map(serde_json::from_value).transpose()?.unwrap_or_default();
            let pairs = labels.get(&key).cloned()
                .unwrap_or_else(|| previous_labels.into_iter().collect());
            let value = values.get(&key).cloned().or(persisted.as_ref()
                .map(|p| p.try_get::<String, _>("trigger_value")).transpose()?).unwrap_or_default();
            let candidate_host = pairs
                .iter()
                .find(|(k, _)| k == "host")
                .map(|(_, v)| v.clone())
                .or(persisted.as_ref().map(|p| p.try_get::<Option<String>, _>("host_name")).transpose()?.flatten())
                .or(row.try_get::<Option<String>, _>("host_name")?);
            let host = if let Some(name) = candidate_host.as_ref() {
                sqlx::query("SELECT id,host_group_id FROM hosts WHERE tenant_id=$1 AND name=$2")
                    .bind(tenant)
                    .bind(name)
                    .fetch_optional(&mut *tx)
                    .await?
            } else if let TriggerState::Problem { problem_id, .. } = &previous {
                sqlx::query("SELECT h.id,h.host_group_id FROM problems p JOIN hosts h ON h.tenant_id=p.tenant_id AND h.id=p.host_id WHERE p.tenant_id=$1 AND p.id=$2").bind(tenant).bind(problem_id).fetch_optional(&mut *tx).await?
            } else {
                None
            };
            let host_id = host
                .as_ref()
                .map(|h| h.try_get::<Uuid, _>("id"))
                .transpose()?;
            let group = host
                .as_ref()
                .map(|h| h.try_get::<Option<Uuid>, _>("host_group_id"))
                .transpose()?
                .flatten();
            let mut firing = labels.contains_key(&key) && !recovered.contains(&key);
            if !matches!(previous, TriggerState::Problem { .. })
                && maintenance::problems_suppressed(&windows, host_id, group, now)
            {
                firing = false;
            }
            let transition = rules::step(
                &previous,
                firing,
                now.timestamp(),
                row.try_get::<i32, _>("for_seconds")? as i64,
                row.try_get::<i32, _>("recover_for")? as i64,
                Uuid::new_v4(),
            );
            if let TriggerState::Problem { problem_id, .. } = &previous {
                if values.contains_key(&key) {
                    sqlx::query("UPDATE problems SET trigger_value=$3 WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(problem_id).bind(&value).execute(&mut *tx).await?;
                }
            }
            if let Some(event) = transition.event {
                let name: String = row.try_get("name")?;
                let severity: String = row.try_get("severity")?;
                let status = if event.kind == EventKind::Opened {
                    "problem"
                } else {
                    "resolved"
                };
                if event.kind == EventKind::Opened {
                    let json_labels: BTreeMap<_, _> = pairs.into_iter().collect();
                    sqlx::query("INSERT INTO problems(id,tenant_id,trigger_id,host_id,status,severity,opened_at,instance_hash,labels,trigger_value) VALUES($1,$2,$3,$4,'problem',$5,$6,$7,$8,$9)").bind(event.problem_id).bind(tenant).bind(trigger_id).bind(host_id).bind(&severity).bind(now).bind(&key).bind(json!(json_labels)).bind(&value).execute(&mut *tx).await?;
                } else {
                    sqlx::query("UPDATE problems SET status='resolved',resolved_at=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(event.problem_id).bind(now).execute(&mut *tx).await?;
                }
                sqlx::query("INSERT INTO problem_events(tenant_id,problem_id,kind,detail) VALUES($1,$2,$3,$4)").bind(tenant).bind(event.problem_id).bind(status).bind(json!({"trigger":name,"instance":key})).execute(&mut *tx).await?;
                queue_notifications(
                    &mut tx,
                    tenant,
                    event.problem_id,
                    status,
                    &name,
                    candidate_host.as_deref().unwrap_or("unknown"),
                    &value,
                )
                .await?;
                let mut finding = crate::forward::detection_finding(
                    &name,
                    candidate_host.as_deref().unwrap_or("unknown"),
                    status,
                    &severity,
                );
                finding["finding_info"]["uid"] = json!(event.problem_id);
                enqueue_forward(&mut tx, tenant, status, &finding).await?;
                notes.push(ProblemNote {
                    tenant_id: tenant,
                    problem_id: event.problem_id,
                    kind: status.into(),
                });
            }
            match transition.state {
                TriggerState::Ok => {
                    sqlx::query("DELETE FROM trigger_state WHERE tenant_id=$1 AND trigger_id=$2 AND instance_hash=$3").bind(tenant).bind(trigger_id).bind(&key).execute(&mut *tx).await?;
                }
                value => {
                    let (name, since, problem, recover) = match value {
                        TriggerState::Pending { since } => ("pending", since, None, None),
                        TriggerState::Problem {
                            problem_id,
                            recover_since,
                        } => ("problem", now.timestamp(), Some(problem_id), recover_since),
                        TriggerState::Ok => unreachable!(),
                    };
                    sqlx::query("INSERT INTO trigger_state(tenant_id,trigger_id,instance_hash,state,since,problem_id,recover_since) VALUES($1,$2,$3,$4,to_timestamp($5),$6,to_timestamp($7)) ON CONFLICT(tenant_id,trigger_id,instance_hash) DO UPDATE SET state=excluded.state,since=excluded.since,problem_id=excluded.problem_id,recover_since=excluded.recover_since").bind(tenant).bind(trigger_id).bind(&key).bind(name).bind(since as f64).bind(problem).bind(recover.map(|v|v as f64)).execute(&mut *tx).await?;
                }
            }
        }
        sqlx::query("INSERT INTO trigger_evaluations(tenant_id,trigger_id,evaluated_at) VALUES($1,$2,$3) ON CONFLICT(tenant_id,trigger_id) DO UPDATE SET evaluated_at=excluded.evaluated_at").bind(tenant).bind(trigger_id).bind(now).execute(&mut *tx).await?;
        tx.commit().await?;
        for note in notes {
            let _ = state.events.send(note);
        }
        Ok(())
        }.await;
        if let Err(err) = result {
            tracing::warn!(error=%err,"trigger evaluation failed; other rules continue");
        }
    }
    Ok(())
}

async fn queue_notifications(
    conn: &mut PgConnection,
    tenant: Uuid,
    problem: Uuid,
    status: &str,
    trigger: &str,
    host: &str,
    value: &str,
) -> Result<()> {
    let actions=sqlx::query("SELECT a.id,a.media_type_id,s.step,s.delay_s,s.media_type_ids FROM actions a LEFT JOIN action_steps s ON s.tenant_id=a.tenant_id AND s.action_id=a.id WHERE a.tenant_id=$1").bind(tenant).fetch_all(&mut *conn).await?;
    for action in actions {
        let step = action.try_get::<Option<i32>, _>("step")?.unwrap_or(0);
        let delay = if status == "resolved" {
            0
        } else {
            action.try_get::<Option<i32>, _>("delay_s")?.unwrap_or(0)
        };
        let mut media: Vec<Uuid> = serde_json::from_value(
            action
                .try_get::<Option<Value>, _>("media_type_ids")?
                .unwrap_or(json!([])),
        )
        .unwrap_or_else(|_| {
            tracing::warn!(%tenant,"ignoring malformed notification step targets");
            Vec::new()
        });
        if let Some(id) = action.try_get::<Option<Uuid>, _>("media_type_id")? {
            media.push(id);
        }
        media.sort();
        media.dedup();
        for id in media {
            sqlx::query("INSERT INTO notification_jobs(tenant_id,problem_id,media_type_id,status,payload,run_after) SELECT $1,$2,id,'pending',$4,now()+make_interval(secs=>$5) FROM media_types WHERE tenant_id=$1 AND id=$3 AND kind NOT IN ('wedgetail','syslog','siem_webhook') ON CONFLICT DO NOTHING").bind(tenant).bind(problem).bind(id).bind(json!({"event":status,"step":if status=="resolved"{0}else{step},"trigger":trigger,"host":host,"value":value,"problem_id":problem})).bind(delay as f64).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

async fn deliver_one(state: &ApiState, public_url: &str, forward: bool) -> Result<bool> {
    let db = state.db.as_ref().ok_or("database unavailable")?;
    let mut tx = db.pool.begin().await?;
    let table = if forward {
        "forward_jobs"
    } else {
        "notification_jobs"
    };
    let sql=format!("SELECT * FROM {table} WHERE status='pending' AND run_after<=now() ORDER BY run_after,id FOR UPDATE SKIP LOCKED LIMIT 1");
    let Some(job) = sqlx::query(&sql).fetch_optional(&mut *tx).await? else {
        return Ok(false);
    };
    let tenant: Uuid = job.try_get("tenant_id")?;
    let id: Uuid = job.try_get("id")?;
    let payload: Value = job.try_get("payload")?;
    let media_id: Option<Uuid> = if forward {
        serde_json::from_value(payload["media_type_id"].clone()).ok()
    } else {
        Some(job.try_get("media_type_id")?)
    };
    let problem: Option<Uuid> = if forward {
        None
    } else {
        job.try_get("problem_id")?
    };
    if let Some(problem) = problem {
        let p=sqlx::query("SELECT p.status,p.acknowledged_at,p.host_id,h.host_group_id FROM problems p LEFT JOIN hosts h ON h.tenant_id=p.tenant_id AND h.id=p.host_id WHERE p.tenant_id=$1 AND p.id=$2").bind(tenant).bind(problem).fetch_one(&mut *tx).await?;
        let host = p.try_get("host_id")?;
        let group = p.try_get("host_group_id")?;
        let status: String = p.try_get("status")?;
        let ack: Option<DateTime<Utc>> = p.try_get("acknowledged_at")?;
        if payload["event"] != "resolved" && (status == "resolved" || ack.is_some()) {
            sqlx::query("UPDATE notification_jobs SET status='sent',last_error='cancelled after acknowledgement or resolution' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(true);
        }
        if maintenance::notifications_suppressed(
            &windows(&mut tx, tenant).await?,
            host,
            group,
            Utc::now(),
        ) {
            sqlx::query("UPDATE notification_jobs SET run_after=now()+interval '30 seconds' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(true);
        }
    }
    let media = sqlx::query("SELECT kind,config FROM media_types WHERE tenant_id=$1 AND id=$2")
        .bind(tenant)
        .bind(media_id)
        .fetch_optional(&mut *tx)
        .await?;
    let outcome: Result<()> = async {
        let media = media.ok_or("media type no longer exists")?;
        let kind: String = media.try_get("kind")?;
        let config: Value = media.try_get("config")?;
        let mut config = if let Some(encrypted) = config.get("encrypted").and_then(Value::as_str) {
            serde_json::from_str(
                &state
                    .secrets
                    .as_ref()
                    .ok_or("secret identity unavailable")?
                    .decrypt(encrypted)?,
            )?
        } else {
            config
        };
        config = notify::with_smtp_defaults(config, state.smtp.as_ref());
        config
            .as_object_mut()
            .ok_or("media configuration must be an object")?
            .insert("kind".to_string(), json!(kind));
        if forward {
            let event = ForwardEvent {
                tenant_id: tenant,
                kind: job.try_get("kind")?,
                body: payload["event"].clone(),
            };
            match kind.as_str() {
                "wedgetail" => {
                    WedgetailForwarder::new(required(&config, "url")?, required(&config, "token")?)
                        .forward(&event)
                        .await?
                }
                "siem_webhook" => {
                    WebhookForwarder::new(required(&config, "url")?, required(&config, "secret")?)
                        .forward(&event)
                        .await?
                }
                "syslog" => {
                    crate::forward::send_syslog_tls_with_ca(
                        required(&config, "host")?,
                        u16::try_from(config["port"].as_u64().unwrap_or(6514))
                            .ok()
                            .filter(|port| *port != 0)
                            .ok_or("invalid syslog port")?,
                        &event.body.to_string(),
                        config["ca_pem"].as_str(),
                    )
                    .await?
                }
                _ => return Err("unsupported forwarding kind".into()),
            }
        } else {
            let rendered = notify::render_for_target(
                payload["problem_id"].as_str().unwrap_or(""),
                payload["trigger"].as_str().unwrap_or("problem"),
                payload["host"].as_str().unwrap_or("unknown"),
                payload["trigger"].as_str().unwrap_or(""),
                payload["value"].as_str().unwrap_or(""),
                &format!("{public_url}/problems"),
                payload["event"].as_str().unwrap_or("problem"),
                &config,
            )?;
            if kind == "email" {
                tokio::time::timeout(
                    Duration::from_secs(10),
                    notify::send_smtp(&rendered, &config),
                )
                .await??
            } else {
                notify::HttpNotifier::new().send(&rendered, &config).await?
            }
        }
        Ok(())
    }
    .await;
    let attempts = job.try_get::<i32, _>("attempts")? + 1;
    let (status, error) = match outcome {
        Ok(()) => ("sent", None),
        Err(_) => (
            if attempts >= 10 { "failed" } else { "pending" },
            Some("delivery failed; check target configuration"),
        ),
    };
    sqlx::query(&format!("UPDATE {table} SET status=$3,attempts=$4,last_error=$5,run_after=now()+make_interval(secs=>$6) WHERE tenant_id=$1 AND id=$2")).bind(tenant).bind(id).bind(status).bind(attempts).bind(error).bind(notify::backoff_seconds(attempts) as f64).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(true)
}

fn required<'a>(config: &'a Value, key: &str) -> Result<&'a str> {
    config[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("missing {key}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{LabelledSample, MetricStore, Series};
    use async_trait::async_trait;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::str::FromStr;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    };

    struct Signal {
        firing: AtomicBool,
        tenant: Uuid,
        include_host: AtomicBool,
        value: AtomicU64,
    }
    #[async_trait]
    impl MetricStore for Signal {
        async fn write(
            &self,
            _: Vec<LabelledSample>,
        ) -> std::result::Result<(), crate::ServerError> {
            Ok(())
        }
        async fn query(
            &self,
            expr: &str,
            at: i64,
        ) -> std::result::Result<Vec<Series>, crate::ServerError> {
            assert!(
                expr.contains(&format!("tenant=\"{}\"", self.tenant)),
                "unscoped evaluator: {expr}"
            );
            Ok(if self.firing.load(Ordering::SeqCst) {
                vec![Series {
                    labels: if self.include_host.load(Ordering::SeqCst) {
                        vec![
                            ("host".into(), "web-1".into()),
                            ("tenant".into(), self.tenant.to_string()),
                        ]
                    } else {
                        vec![("tenant".into(), self.tenant.to_string())]
                    },
                    points: vec![
                        (at - 1, 94.0),
                        (at, self.value.load(Ordering::SeqCst) as f64),
                    ],
                }]
            } else {
                vec![]
            })
        }
        async fn query_range(
            &self,
            _: &str,
            _: i64,
            _: i64,
            _: u32,
        ) -> std::result::Result<Vec<Series>, crate::ServerError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn durable_workers_restart_retry_resolve_ack_and_maintenance() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset; skipping durable worker integration");
            return;
        };
        let opts = PgConnectOptions::from_str(&url).unwrap();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(opts.clone())
            .await
            .unwrap();
        let name = format!("kestrel_workers_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(opts.database(&name))
            .await
            .unwrap();
        let db = crate::db::Db::from_pool(pool).await.unwrap();
        let outcome:Result<()>=async {
            let tenant=crate::store::DEFAULT_TENANT_ID;
            let host=Uuid::new_v4();let trigger=Uuid::new_v4();let medium=Uuid::new_v4();
            sqlx::query("INSERT INTO hosts(id,tenant_id,name) VALUES($1,$2,'web-1')").bind(host).bind(tenant).execute(&db.pool).await?;
            sqlx::query("INSERT INTO triggers(id,tenant_id,host_id,name,expression,severity) VALUES($1,$2,$3,'disk full','kestrel_disk_used > 90','high')").bind(trigger).bind(tenant).bind(host).execute(&db.pool).await?;
            // A tenant-wide trigger derives its host from the firing series;
            // recovery must retain that context after the series disappears.
            sqlx::query("UPDATE triggers SET host_id=NULL WHERE id=$1").bind(trigger).execute(&db.pool).await?;
            let hook=wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST")).respond_with(wiremock::ResponseTemplate::new(200)).mount(&hook).await;
            sqlx::query("INSERT INTO media_types(id,tenant_id,name,kind,config) VALUES($1,$2,'hook','webhook',$3)").bind(medium).bind(tenant).bind(json!({"url":hook.uri(),"secret":"local-test"})).execute(&db.pool).await?;
            sqlx::query("INSERT INTO actions(tenant_id,name,media_type_id) VALUES($1,'page',$2)").bind(tenant).bind(medium).execute(&db.pool).await?;
            // A malformed legacy step must not roll back problem creation.
            sqlx::query("INSERT INTO action_steps(tenant_id,action_id,step,media_type_ids) SELECT tenant_id,id,0,$2 FROM actions WHERE tenant_id=$1").bind(tenant).bind(json!(["invalid-legacy-uuid"])).execute(&db.pool).await?;
            let signal=Arc::new(Signal{firing:AtomicBool::new(true),tenant,include_host:AtomicBool::new(true),value:AtomicU64::new(95)});
            let state=ApiState::new(Arc::new(crate::api::MemoryCatalog::new()),signal.clone()).with_database(db.clone(),Arc::new(crate::secrets::SecretBox::load_or_create(&std::env::temp_dir().join(format!("{name}.key")))?));
            evaluate(&state).await?;
            let problem:Uuid=sqlx::query_scalar("SELECT id FROM problems WHERE tenant_id=$1").bind(tenant).fetch_one(&db.pool).await?;
            assert!(deliver_one(&state,"https://monitor.example",false).await?);
            assert_eq!(hook.received_requests().await.unwrap().len(),1);
            let opening:Value=serde_json::from_slice(&hook.received_requests().await.unwrap()[0].body)?;
            assert_eq!(opening["subject"],"disk full on web-1");
            assert!(opening["body"].as_str().unwrap().contains("95"),"notification must contain the actual firing value");
            // Simulate a fresh evaluator after restart; state in PostgreSQL wins.
            signal.value.store(96,Ordering::SeqCst);
            sqlx::query("DELETE FROM trigger_evaluations").execute(&db.pool).await?;
            evaluate(&state.clone()).await?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM problems").fetch_one(&db.pool).await?;assert_eq!(count,1);
            signal.firing.store(false,Ordering::SeqCst);
            sqlx::query("DELETE FROM trigger_evaluations").execute(&db.pool).await?;
            evaluate(&state).await?;
            let status:String=sqlx::query_scalar("SELECT status FROM problems WHERE id=$1").bind(problem).fetch_one(&db.pool).await?;assert_eq!(status,"resolved");
            assert!(deliver_one(&state,"https://monitor.example",false).await?);
            let requests=hook.received_requests().await.unwrap();assert_eq!(requests.len(),2);
            let resolution:Value=serde_json::from_slice(&requests[1].body)?;assert_eq!(resolution["status"],"resolved");assert_eq!(resolution["problem_id"],problem.to_string());
            assert_eq!(resolution["subject"],"disk full on web-1","recovery must retain a tenant-wide trigger's series host");
            assert!(resolution["body"].as_str().unwrap().contains("96"),"recovery must retain the latest firing value across evaluator restarts");
            let retained:Value=sqlx::query_scalar("SELECT labels FROM problems WHERE id=$1").bind(problem).fetch_one(&db.pool).await?;
            assert_eq!(retained["host"],"web-1","recovery must preserve series labels");
            // Reopen, then exercise maintenance deferral, failure retry and ack.
            sqlx::query("UPDATE triggers SET host_id=$1 WHERE id=$2").bind(host).bind(trigger).execute(&db.pool).await?;
            signal.firing.store(true,Ordering::SeqCst);
            signal.include_host.store(false,Ordering::SeqCst);
            sqlx::query("DELETE FROM trigger_evaluations").execute(&db.pool).await?;
            evaluate(&state).await?;
            let job:Uuid=sqlx::query_scalar("SELECT id FROM notification_jobs WHERE status='pending'").fetch_one(&db.pool).await?;
            let assigned:Uuid=sqlx::query_scalar("SELECT host_id FROM problems WHERE status='problem'").fetch_one(&db.pool).await?;
            assert_eq!(assigned,host,"aggregation must retain the configured host for RBAC and maintenance");
            sqlx::query("INSERT INTO maintenances(tenant_id,name,starts_at,ends_at,suppress_problems,host_ids) VALUES($1,'quiet',now()-interval '1 minute',now()+interval '1 minute',false,$2)").bind(tenant).bind(json!([host])).execute(&db.pool).await?;
            assert!(deliver_one(&state,"https://monitor.example",false).await?);
            assert_eq!(hook.received_requests().await.unwrap().len(),2);
            sqlx::query("DELETE FROM maintenances").execute(&db.pool).await?;
            hook.reset().await;
            wiremock::Mock::given(wiremock::matchers::method("POST")).respond_with(wiremock::ResponseTemplate::new(500)).mount(&hook).await;
            sqlx::query("UPDATE notification_jobs SET run_after=now() WHERE id=$1").bind(job).execute(&db.pool).await?;
            assert!(deliver_one(&state,"https://monitor.example",false).await?);
            let row=sqlx::query("SELECT status,attempts,last_error FROM notification_jobs WHERE id=$1").bind(job).fetch_one(&db.pool).await?;
            assert_eq!(row.try_get::<String,_>("status")?,"pending");assert_eq!(row.try_get::<i32,_>("attempts")?,1);assert!(row.try_get::<Option<String>,_>("last_error")?.is_some());
            sqlx::query("UPDATE problems SET acknowledged_at=now() WHERE status='problem'").execute(&db.pool).await?;
            sqlx::query("UPDATE notification_jobs SET run_after=now() WHERE id=$1").bind(job).execute(&db.pool).await?;
            assert!(deliver_one(&state,"https://monitor.example",false).await?);
            assert_eq!(hook.received_requests().await.unwrap().len(),1,"ack must cancel retry");
            sqlx::query("UPDATE triggers SET enabled=false,expression='invalid )'").execute(&db.pool).await?;
            sqlx::query("DELETE FROM trigger_evaluations").execute(&db.pool).await?;
            evaluate(&state).await?;
            let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM problems WHERE status='problem'").fetch_one(&db.pool).await?;
            assert_eq!(remaining,0,"disabled discovery triggers must resolve their existing problems");
            let _=std::fs::remove_file(std::env::temp_dir().join(format!("{name}.key")));
            Ok(())
        }.await;
        db.pool.close().await;
        sqlx::raw_sql(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&admin)
            .await
            .unwrap();
        outcome.unwrap();
    }
}
