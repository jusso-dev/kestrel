use super::{db_err, Db};
use crate::{
    ingest::PreparedBatch,
    store::{EnrolledAgent, MetricStore},
    ServerError,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Prefix of enrolment errors that map to HTTP 409.
pub(crate) const HOST_CONFLICT: &str = "enrolment host conflict";

/// The existing host named `hostname`, if `agent` may bind to it.
///
/// Host names are unique per tenant, so a name that is already taken can only
/// be bound when the host sits in the token's group (if it has one) and no
/// other agent is active on it. Otherwise enrolment is refused rather than
/// taking over another host's identity.
async fn bindable_host(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: Uuid,
    hostname: &str,
    group: Option<Uuid>,
    agent: Uuid,
) -> Result<Option<Uuid>, ServerError> {
    let existing: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id,host_group_id FROM hosts WHERE tenant_id=$1 AND name=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(hostname)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err)?;
    let Some((host, host_group)) = existing else {
        return Ok(None);
    };
    if group.is_some() && host_group != group {
        return Err(ServerError::new(format!(
            "{HOST_CONFLICT}: host {hostname} is outside the token's host group"
        )));
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE tenant_id=$1 AND host_id=$2 AND id<>$3 AND revoked_at IS NULL)",
    )
    .bind(tenant)
    .bind(host)
    .bind(agent)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    if active {
        return Err(ServerError::new(format!(
            "{HOST_CONFLICT}: host {hostname} already has an active agent; revoke it first"
        )));
    }
    Ok(Some(host))
}

impl Db {
    async fn apply_inventory(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: Uuid,
        host: Uuid,
        inventory: &kestrel_proto::v1::Inventory,
    ) -> Result<(), ServerError> {
        use serde_json::{json, Value};
        use std::collections::BTreeMap;
        let mut entities: Vec<(&str, String, BTreeMap<String, String>)> = Vec::new();
        for fs in &inventory.filesystems {
            entities.push((
                "filesystem",
                fs.mount.clone(),
                BTreeMap::from([
                    ("MOUNT".into(), fs.mount.clone()),
                    ("DEVICE".into(), fs.device.clone()),
                    ("FSTYPE".into(), fs.fs_type.clone()),
                ]),
            ));
        }
        for interface in &inventory.interfaces {
            entities.push((
                "interface",
                interface.name.clone(),
                BTreeMap::from([
                    ("IFNAME".into(), interface.name.clone()),
                    ("NAME".into(), interface.name.clone()),
                    ("MAC".into(), interface.mac.clone()),
                ]),
            ));
        }
        for service in &inventory.services {
            entities.push((
                "service",
                service.name.clone(),
                BTreeMap::from([
                    ("NAME".into(), service.name.clone()),
                    ("SERVICE".into(), service.name.clone()),
                    ("MANAGER".into(), service.manager.clone()),
                    ("STATE".into(), service.state.clone()),
                ]),
            ));
        }
        for port in &inventory.listen_ports {
            let key = format!("{}:{}:{}", port.protocol, port.address, port.port);
            entities.push((
                "port",
                key,
                BTreeMap::from([
                    ("ADDRESS".into(), port.address.clone()),
                    ("PORT".into(), port.port.to_string()),
                    ("PROTOCOL".into(), port.protocol.clone()),
                ]),
            ));
        }
        let rules:Vec<(Uuid,String,String,String,String,i32)>=sqlx::query_as("WITH RECURSIVE linked(id) AS (SELECT template_id FROM template_links WHERE tenant_id=$1 AND host_id=$2 UNION SELECT p.parent_id FROM template_parents p JOIN linked l ON p.template_id=l.id WHERE p.tenant_id=$1) SELECT r.id,r.entity,r.filter,r.item_prototype,r.trigger_prototype,r.keep_days FROM discovery_rules r JOIN linked l ON r.template_id=l.id WHERE r.tenant_id=$1").bind(tenant).bind(host).fetch_all(&mut **tx).await.map_err(db_err)?;
        for (rule, entity, filter, item_prototype, trigger_prototype, keep_days) in rules {
            for (kind, key, labels) in &entities {
                if *kind != entity || !crate::discovery::filter_matches(key, &filter) {
                    continue;
                }
                let entity_id:Uuid=sqlx::query_scalar("INSERT INTO discovered_entities (tenant_id,host_id,rule_id,entity_key,labels,last_seen) VALUES ($1,$2,$3,$4,$5,now()) ON CONFLICT (tenant_id,host_id,rule_id,entity_key) DO UPDATE SET labels=EXCLUDED.labels,last_seen=now(),updated_at=now() RETURNING id").bind(tenant).bind(host).bind(rule).bind(key).bind(json!(labels)).fetch_one(&mut **tx).await.map_err(db_err)?;
                if !item_prototype.is_empty() {
                    let item: Value = crate::discovery::prototype_item(&item_prototype, labels);
                    let key = item["key"]
                        .as_str()
                        .ok_or_else(|| ServerError::new("discovery item key required"))?;
                    let kind = item["kind"]
                        .as_str()
                        .ok_or_else(|| ServerError::new("discovery item kind required"))?;
                    let interval = item["interval_s"].as_i64().unwrap_or(30);
                    sqlx::query("INSERT INTO items (tenant_id,host_id,discovered_entity_id,key,kind,interval_s,params) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,host_id,key) DO UPDATE SET kind=EXCLUDED.kind,interval_s=EXCLUDED.interval_s,params=EXCLUDED.params WHERE items.discovered_entity_id=EXCLUDED.discovered_entity_id").bind(tenant).bind(host).bind(entity_id).bind(key).bind(kind).bind(i32::try_from(interval).map_err(|_|ServerError::new("invalid discovery interval"))?).bind(item.get("params").cloned().unwrap_or(json!({}))).execute(&mut **tx).await.map_err(db_err)?;
                }
                if !trigger_prototype.is_empty() {
                    let trigger: Value =
                        crate::discovery::prototype_item(&trigger_prototype, labels);
                    let name = trigger["name"]
                        .as_str()
                        .ok_or_else(|| ServerError::new("discovery trigger name required"))?;
                    let expression = trigger["expression"]
                        .as_str()
                        .ok_or_else(|| ServerError::new("discovery expression required"))?;
                    crate::promql::inject_scope(expression, &tenant.to_string(), None)
                        .map_err(ServerError::new)?;
                    sqlx::query("INSERT INTO triggers (tenant_id,host_id,discovered_entity_id,name,expression,severity,for_seconds) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,host_id,discovered_entity_id,name) WHERE discovered_entity_id IS NOT NULL DO UPDATE SET expression=EXCLUDED.expression,enabled=true").bind(tenant).bind(host).bind(entity_id).bind(name).bind(expression).bind(trigger["severity"].as_str().unwrap_or("warning")).bind(i32::try_from(trigger["for_seconds"].as_i64().unwrap_or(0)).map_err(|_|ServerError::new("invalid discovery trigger delay"))?).execute(&mut **tx).await.map_err(db_err)?;
                }
            }
            // Disable lost triggers before removing entities so historical
            // problems retain their trigger references.
            sqlx::query("UPDATE triggers SET enabled=false WHERE tenant_id=$1 AND host_id=$2 AND discovered_entity_id IN (SELECT id FROM discovered_entities WHERE tenant_id=$1 AND host_id=$2 AND rule_id=$3 AND last_seen < now()-make_interval(days=>$4))").bind(tenant).bind(host).bind(rule).bind(keep_days).execute(&mut **tx).await.map_err(db_err)?;
            sqlx::query("DELETE FROM discovered_entities WHERE tenant_id=$1 AND host_id=$2 AND rule_id=$3 AND last_seen < now()-make_interval(days=>$4)").bind(tenant).bind(host).bind(rule).bind(keep_days).execute(&mut **tx).await.map_err(db_err)?;
        }
        Ok(())
    }
    /// Resolve an enrolment token's host group, given by id or name.
    async fn enrolment_group(
        &self,
        tenant: Uuid,
        group: Option<&str>,
    ) -> Result<Option<Uuid>, ServerError> {
        let Some(value) = group else {
            return Ok(None);
        };
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM host_groups WHERE tenant_id=$1 AND (id::text=$2 OR name=$2)",
        )
        .bind(tenant)
        .bind(value)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ServerError::new("unknown enrolment host group"))
        .map(Some)
    }

    /// Refuse an enrolment that would take over an existing host it may not bind.
    pub(crate) async fn check_enrolment_host(
        &self,
        tenant: Uuid,
        hostname: &str,
        group: Option<&str>,
    ) -> Result<(), ServerError> {
        let group = self.enrolment_group(tenant, group).await?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        bindable_host(&mut tx, tenant, hostname, group, Uuid::nil()).await?;
        Ok(())
    }

    /// Reconcile the durable certificate directory with the SQL host inventory.
    /// Repeated calls retain host identity and sequence acknowledgement.
    pub(crate) async fn ensure_enrolled_agent(
        &self,
        agent: &EnrolledAgent,
    ) -> Result<Uuid, ServerError> {
        // An established binding survives certificate renewal and later host
        // group moves; enrolment group rules apply only when first binding.
        let existing: Option<(Uuid, String)> = sqlx::query_as("SELECT host_id,cert_serial FROM agents WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL AND host_id IS NOT NULL").bind(agent.tenant_id).bind(agent.id).fetch_optional(&self.pool).await.map_err(db_err)?;
        if let Some((host, serial)) = existing {
            if serial != agent.cert_serial {
                let expires = DateTime::parse_from_rfc3339(&agent.cert_not_after)
                    .map_err(|_| ServerError::new("invalid certificate expiry"))?
                    .with_timezone(&Utc);
                sqlx::query("UPDATE agents SET cert_serial=$3,cert_not_after=$4 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL").bind(agent.tenant_id).bind(agent.id).bind(&agent.cert_serial).bind(expires).execute(&self.pool).await.map_err(db_err)?;
            }
            return Ok(host);
        }
        let group = self
            .enrolment_group(agent.tenant_id, agent.host_group_id.as_deref())
            .await?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let quota: i32 =
            sqlx::query_scalar("SELECT host_quota FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(agent.tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
        let existing =
            bindable_host(&mut tx, agent.tenant_id, &agent.hostname, group, agent.id).await?;
        let host = if let Some(host) = existing {
            host
        } else {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts WHERE tenant_id=$1")
                .bind(agent.tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
            if count >= i64::from(quota) {
                return Err(ServerError::new("host quota exceeded"));
            }
            sqlx::query_scalar(
                "INSERT INTO hosts (tenant_id,name,host_group_id) VALUES ($1,$2,$3) RETURNING id",
            )
            .bind(agent.tenant_id)
            .bind(&agent.hostname)
            .bind(group)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?
        };
        let expires = DateTime::parse_from_rfc3339(&agent.cert_not_after)
            .map_err(|_| ServerError::new("invalid certificate expiry"))?
            .with_timezone(&Utc);
        sqlx::query("INSERT INTO agents (id,tenant_id,host_id,hostname,os,arch,cert_serial,cert_not_after) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET cert_serial=EXCLUDED.cert_serial,cert_not_after=EXCLUDED.cert_not_after WHERE agents.tenant_id=EXCLUDED.tenant_id AND agents.revoked_at IS NULL").bind(agent.id).bind(agent.tenant_id).bind(host).bind(&agent.hostname).bind(&agent.os).bind(&agent.arch).bind(&agent.cert_serial).bind(expires).execute(&mut *tx).await.map_err(db_err)?;
        if existing.is_none() {
            let name = match agent.os.to_lowercase().as_str() {
                "windows" => "Windows",
                "macos" | "darwin" => "macOS",
                _ => "Linux",
            };
            sqlx::query("INSERT INTO template_links (tenant_id,host_id,template_id) SELECT $1,$2,id FROM templates WHERE tenant_id=$1 AND name=$3 ON CONFLICT DO NOTHING").bind(agent.tenant_id).bind(host).bind(name).execute(&mut *tx).await.map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(host)
    }

    pub(crate) async fn linked_agent_config(
        &self,
        tenant: Uuid,
        host: Uuid,
        name: String,
    ) -> Result<(kestrel_proto::v1::AgentConfig, String), ServerError> {
        use crate::config_compile::{compile_agent_config, HostView, ItemSpec, TemplateDoc};
        use std::collections::BTreeMap;
        let items:Vec<(String,String,i32,serde_json::Value)>=sqlx::query_as("WITH RECURSIVE linked(id,depth,path) AS (SELECT template_id,0,ARRAY[template_id] FROM template_links WHERE tenant_id=$1 AND host_id=$2 UNION ALL SELECT p.parent_id,l.depth+1,l.path||p.parent_id FROM template_parents p JOIN linked l ON p.template_id=l.id WHERE p.tenant_id=$1 AND NOT p.parent_id=ANY(l.path)) SELECT DISTINCT ON (i.key) i.key,i.kind,i.interval_s,i.params FROM items i JOIN linked l ON i.template_id=l.id WHERE i.tenant_id=$1 AND i.host_id IS NULL ORDER BY i.key,l.depth,i.template_id").bind(tenant).bind(host).fetch_all(&self.pool).await.map_err(db_err)?;
        let host_items:Vec<(String,String,i32,serde_json::Value)>=sqlx::query_as("SELECT key,kind,interval_s,params FROM items WHERE tenant_id=$1 AND host_id=$2 ORDER BY key").bind(tenant).bind(host).fetch_all(&self.pool).await.map_err(db_err)?;
        let item =
            |(key, kind, interval_s, params): (String, String, i32, serde_json::Value)| ItemSpec {
                key,
                kind,
                interval_s: interval_s as u32,
                params,
            };
        let overrides = host_items
            .into_iter()
            .map(item)
            .map(|item| (item.key.clone(), item))
            .collect::<BTreeMap<_, _>>();
        // Materialise per-host trigger definitions. The evaluator can now scope
        // the shared template expression to this host without alerting twice.
        let mut conn = self.pool.acquire().await.map_err(db_err)?;
        super::reconcile_template_triggers(&mut conn, tenant, Some(host))
            .await
            .map_err(db_err)?;
        Ok(compile_agent_config(
            &HostView { name, overrides },
            &[TemplateDoc {
                name: "linked".to_string(),
                description: String::new(),
                items: items.into_iter().map(item).collect(),
                triggers: Vec::new(),
            }],
        ))
    }

    /// Acknowledge only after metrics have reached the backend and all other
    /// observations and the sequence have committed atomically. Retried remote
    /// writes use identical timestamps and are idempotent in VictoriaMetrics.
    pub(crate) async fn ingest_prepared(
        &self,
        tenant: Uuid,
        host: Uuid,
        agent: Uuid,
        mut batch: PreparedBatch,
        store: &dyn MetricStore,
    ) -> Result<bool, ServerError> {
        let sequence =
            i64::try_from(batch.seq).map_err(|_| ServerError::new("sequence out of range"))?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let previous:i64=sqlx::query_scalar("SELECT last_seq FROM agents WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL FOR UPDATE").bind(tenant).bind(agent).fetch_one(&mut *tx).await.map_err(db_err)?;
        if sequence <= previous || sequence == 0 {
            return Ok(false);
        }
        let now = Utc::now();
        for sample in &mut batch.samples {
            if sample.name == "kestrel_agent_last_seen_timestamp" {
                sample.value = now.timestamp() as f64;
                sample.timestamp_ms = now.timestamp_millis();
            }
        }
        if !batch
            .samples
            .iter()
            .any(|sample| sample.name == "kestrel_agent_last_seen_timestamp")
        {
            batch.samples.push(crate::LabelledSample {
                name: "kestrel_agent_last_seen_timestamp".to_string(),
                labels: vec![
                    ("tenant".to_string(), tenant.to_string()),
                    (
                        "host".to_string(),
                        sqlx::query_scalar("SELECT name FROM hosts WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant)
                            .bind(host)
                            .fetch_one(&mut *tx)
                            .await
                            .map_err(db_err)?,
                    ),
                    ("agent".to_string(), agent.to_string()),
                ],
                value: now.timestamp() as f64,
                timestamp_ms: now.timestamp_millis(),
            });
        }
        // The backend client timeout bounds this row lock and request lifetime.
        store.write(batch.samples).await?;
        for check in batch.checks {
            let observed = DateTime::from_timestamp_millis(check.timestamp_ms)
                .ok_or_else(|| ServerError::new("invalid check timestamp"))?;
            sqlx::query("INSERT INTO check_results (tenant_id,host_id,agent_id,check_id,state,output,perfdata,observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,host_id,check_id) DO UPDATE SET state=EXCLUDED.state,output=EXCLUDED.output,perfdata=EXCLUDED.perfdata,observed_at=EXCLUDED.observed_at,updated_at=now() WHERE check_results.observed_at <= EXCLUDED.observed_at").bind(tenant).bind(host).bind(agent).bind(check.check_id).bind(check.state).bind(check.output).bind(check.perfdata).bind(observed).execute(&mut *tx).await.map_err(db_err)?;
        }
        if !batch.logs.is_empty() {
            // Serialise partition creation with other ingesters across processes.
            sqlx::query("SELECT pg_advisory_xact_lock(62301845)")
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            let date = now.date_naive();
            let next = date
                .succ_opt()
                .ok_or_else(|| ServerError::new("invalid log date"))?;
            let partition = crate::ingest::log_partition_name(now.timestamp_millis());
            // Bounds are UTC whatever the session time zone, and rows carry the
            // same `now` as created_at. Otherwise database clock skew around
            // midnight files rows into log_events_default, and the next day's
            // partition cannot be created while it holds them.
            sqlx::query(&format!("CREATE TABLE IF NOT EXISTS {partition} PARTITION OF log_events FOR VALUES FROM ('{date} 00:00:00+00') TO ('{next} 00:00:00+00')")).execute(&mut *tx).await.map_err(db_err)?;
            for log in batch.logs {
                let observed = DateTime::from_timestamp_millis(log.timestamp_ms)
                    .ok_or_else(|| ServerError::new("invalid log timestamp"))?;
                let labels = log
                    .labels
                    .into_iter()
                    .map(|label| (label.name, serde_json::Value::String(label.value)))
                    .collect::<serde_json::Map<_, _>>();
                sqlx::query("INSERT INTO log_events (tenant_id,host_id,agent_id,source,line,labels,observed_at,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)").bind(tenant).bind(host).bind(agent).bind(log.source).bind(log.line).bind(serde_json::Value::Object(labels)).bind(observed).bind(now).execute(&mut *tx).await.map_err(db_err)?;
            }
            sqlx::query("DELETE FROM log_events WHERE created_at < now()-make_interval(days=>$1)")
                .bind(self.log_retention_days)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            // Drop whole daily partitions once they age out; the DELETE above
            // only empties them. Names come from the catalogue and must parse
            // as a partition date to qualify.
            let partitions: Vec<String> = sqlx::query_scalar("SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid WHERE i.inhparent='log_events'::regclass")
                .fetch_all(&mut *tx)
                .await
                .map_err(db_err)?;
            for name in partitions {
                if crate::ingest::partition_is_expired(
                    &name,
                    &partition,
                    i64::from(self.log_retention_days),
                ) {
                    sqlx::query(&format!("DROP TABLE IF EXISTS \"{name}\""))
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                }
            }
        }
        if let Some(inventory) = batch.inventory {
            self.apply_inventory(&mut tx, tenant, host, &inventory)
                .await?;
        }
        sqlx::query(
            "UPDATE agents SET last_seq=$3,last_seen_at=now() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant)
        .bind(agent)
        .bind(sequence)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{LabelledSample, MemoryStore, Series};
    use async_trait::async_trait;
    use kestrel_proto::v1;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FailOnce {
        failed: AtomicBool,
        store: MemoryStore,
    }
    #[async_trait]
    impl MetricStore for FailOnce {
        async fn write(&self, samples: Vec<LabelledSample>) -> Result<(), ServerError> {
            if !self.failed.swap(true, Ordering::SeqCst) {
                return Err(ServerError::new("backend unavailable"));
            }
            self.store.write(samples).await
        }
        async fn query(&self, query: &str, at: i64) -> Result<Vec<Series>, ServerError> {
            self.store.query(query, at).await
        }
        async fn query_range(
            &self,
            query: &str,
            start: i64,
            end: i64,
            step: u32,
        ) -> Result<Vec<Series>, ServerError> {
            self.store.query_range(query, start, end, step).await
        }
    }

    #[tokio::test]
    async fn enrolment_does_not_take_over_hosts_outside_group_or_with_active_agents() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let db = Db::connect(&url).await.unwrap();
        let tenant = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
            .bind(tenant)
            .bind(format!("enrol-{tenant}"))
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO host_groups (tenant_id,name) VALUES ($1,'branch')")
            .bind(tenant)
            .execute(&db.pool)
            .await
            .unwrap();
        let agent = |group: Option<&str>| EnrolledAgent {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            hostname: "web".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            cert_serial: "abc".into(),
            cert_not_after: "2030-01-01T00:00:00Z".into(),
            host_group_id: group.map(str::to_string),
        };
        let first = agent(None);
        let host = db.ensure_enrolled_agent(&first).await.unwrap();
        let second = agent(None);
        let err = db.ensure_enrolled_agent(&second).await.unwrap_err();
        assert!(err.to_string().starts_with(HOST_CONFLICT), "{err}");
        assert!(db.check_enrolment_host(tenant, "web", None).await.is_err());
        sqlx::query("UPDATE agents SET revoked_at=now() WHERE id=$1")
            .bind(first.id)
            .execute(&db.pool)
            .await
            .unwrap();
        let grouped = agent(Some("branch"));
        let err = db.ensure_enrolled_agent(&grouped).await.unwrap_err();
        assert!(err.to_string().contains("host group"), "{err}");
        assert!(db
            .check_enrolment_host(tenant, "web", Some("branch"))
            .await
            .is_err());
        db.check_enrolment_host(tenant, "web", None).await.unwrap();
        assert_eq!(db.ensure_enrolled_agent(&second).await.unwrap(), host);
        let names: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts WHERE tenant_id=$1")
            .bind(tenant)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(names, 1);

        // Renewal keeps an established binding after the host changes group.
        let mut branch = agent(Some("branch"));
        branch.hostname = "db".into();
        let db_host = db.ensure_enrolled_agent(&branch).await.unwrap();
        sqlx::query("UPDATE hosts SET host_group_id=NULL WHERE id=$1")
            .bind(db_host)
            .execute(&db.pool)
            .await
            .unwrap();
        let renewed = EnrolledAgent {
            cert_serial: "def".into(),
            ..branch.clone()
        };
        assert_eq!(db.ensure_enrolled_agent(&renewed).await.unwrap(), db_host);
        let serial: String = sqlx::query_scalar("SELECT cert_serial FROM agents WHERE id=$1")
            .bind(branch.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(serial, "def");
    }

    #[tokio::test]
    async fn ingest_postgres_retries_without_acknowledging_and_discovers_entities() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let db = Db::connect(&url).await.unwrap();
        let tenant = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
            .bind(tenant)
            .bind(format!("ingest-{tenant}"))
            .execute(&db.pool)
            .await
            .unwrap();
        let agent = EnrolledAgent {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            hostname: "db-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            cert_serial: "abc".into(),
            cert_not_after: "2030-01-01T00:00:00Z".into(),
            host_group_id: None,
        };
        let host = db.ensure_enrolled_agent(&agent).await.unwrap();
        // An aged-out daily partition is dropped by the next log ingest.
        sqlx::query("CREATE TABLE IF NOT EXISTS log_events_2000_01_01 PARTITION OF log_events FOR VALUES FROM ('2000-01-01 00:00:00+00') TO ('2000-01-02 00:00:00+00')")
            .execute(&db.pool)
            .await
            .unwrap();
        let template: Uuid = sqlx::query_scalar(
            "INSERT INTO templates (tenant_id,name) VALUES ($1,'Disks') RETURNING id",
        )
        .bind(tenant)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO template_links (tenant_id,host_id,template_id) VALUES ($1,$2,$3)")
            .bind(tenant)
            .bind(host)
            .bind(template)
            .execute(&db.pool)
            .await
            .unwrap();
        let rule:Uuid=sqlx::query_scalar("INSERT INTO discovery_rules (tenant_id,template_id,name,entity,item_prototype,trigger_prototype,keep_days) VALUES ($1,$2,'filesystems','filesystem',$3,$4,0) RETURNING id").bind(tenant).bind(template).bind(json!({"key":"disk[{#MOUNT}]","kind":"builtin","interval_s":30,"params":{"collector":"filesystem"}}).to_string()).bind(json!({"name":"disk[{#MOUNT}]","expression":"kestrel_filesystem_used_ratio{mount=\"{#MOUNT}\"} > 0.9","severity":"high","for_seconds":0}).to_string()).fetch_one(&db.pool).await.unwrap();
        let now = Utc::now().timestamp_millis();
        let batch = v1::Batch {
            agent_id: agent.id.to_string(),
            seq: 1,
            samples: vec![v1::Sample {
                name: "ingest_test_value".into(),
                labels: vec![],
                value: 42.0,
                timestamp_ms: now,
            }],
            checks: vec![v1::CheckResult {
                check_id: "disk".into(),
                state: 2,
                output: "full".into(),
                perfdata: "used=95%".into(),
                timestamp_ms: now,
            }],
            logs: vec![v1::LogEvent {
                source: "test".into(),
                line: "line".into(),
                timestamp_ms: now,
                labels: vec![],
            }],
            inventory: Some(v1::Inventory {
                filesystems: vec![v1::Filesystem {
                    mount: "/data".into(),
                    device: "sda1".into(),
                    fs_type: "ext4".into(),
                }],
                ..Default::default()
            }),
        };
        let prepare = |batch| {
            crate::ingest::label_batch(batch, &tenant.to_string(), "db-host", &agent.id.to_string())
        };
        let store = FailOnce {
            failed: AtomicBool::new(false),
            store: MemoryStore::new(),
        };
        assert!(db
            .ingest_prepared(tenant, host, agent.id, prepare(batch.clone()), &store)
            .await
            .is_err());
        let last: i64 = sqlx::query_scalar("SELECT last_seq FROM agents WHERE id=$1")
            .bind(agent.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(last, 0);
        assert!(db
            .ingest_prepared(tenant, host, agent.id, prepare(batch.clone()), &store)
            .await
            .unwrap());
        assert!(!db
            .ingest_prepared(tenant, host, agent.id, prepare(batch.clone()), &store)
            .await
            .unwrap());
        let checks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM check_results WHERE tenant_id=$1 AND host_id=$2",
        )
        .bind(tenant)
        .bind(host)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(checks, 1);
        let logs: i64 = sqlx::query_scalar("SELECT count(*) FROM log_events WHERE tenant_id=$1")
            .bind(tenant)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(logs, 1);
        let partition = crate::ingest::log_partition_name(Utc::now().timestamp_millis());
        let partitioned: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {partition} WHERE tenant_id=$1"
        ))
        .bind(tenant)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            partitioned, 1,
            "rows must land in the partition named for them"
        );
        let expired: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('log_events_2000_01_01')::text")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert!(expired.is_none(), "expired partitions must be dropped");
        let entities: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM discovered_entities WHERE tenant_id=$1 AND rule_id=$2",
        )
        .bind(tenant)
        .bind(rule)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(entities, 1);
        let (config, _) = db
            .linked_agent_config(tenant, host, "db-host".into())
            .await
            .unwrap();
        assert!(config.items.iter().any(|item| item.key == "disk[/data]"));
        let mut lost = batch.clone();
        lost.seq = 2;
        lost.inventory = Some(v1::Inventory::default());
        db.ingest_prepared(tenant, host, agent.id, prepare(lost), &store)
            .await
            .unwrap();
        let enabled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM triggers WHERE tenant_id=$1 AND host_id=$2 AND enabled",
        )
        .bind(tenant)
        .bind(host)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(enabled, 0);
        if let Ok(url) = std::env::var("VICTORIA_URL") {
            let remote = crate::store::VictoriaStore::new(&url).unwrap();
            let mut real = batch;
            real.seq = 3;
            assert!(db
                .ingest_prepared(tenant, host, agent.id, prepare(real), &remote)
                .await
                .unwrap());
            let expr = format!("ingest_test_value{{tenant=\"{tenant}\"}}");
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
            loop {
                let series = remote.query(&expr, Utc::now().timestamp()).await.unwrap();
                if !series.is_empty() {
                    assert_eq!(series.len(), 1);
                    assert_eq!(series[0].points.last().unwrap().1, 42.0);
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "accepted metrics did not become queryable"
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}
