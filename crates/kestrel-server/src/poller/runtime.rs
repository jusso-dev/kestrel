//! Reload encrypted device configurations and poll each device independently.

use super::snmp::{
    BlockingPoller, SnmpPoller, SnmpTarget, SnmpVar, SnmpVersion, TimeoutPool, DEFAULT_PERMITS,
    IF_TABLE, IF_X_TABLE,
};
use crate::{api::ApiState, db::Db, secrets::SecretBox, LabelledSample};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

type Error = Box<dyn std::error::Error + Send + Sync>;

// Parents are applied before children; host overrides are applied last.
// Track paths to terminate even if an operator imports a cyclic graph.
const ITEMS_SQL: &str = r#"
WITH RECURSIVE linked(id,depth,path) AS (
  SELECT template_id,0,ARRAY[template_id] FROM template_links WHERE tenant_id=$1 AND host_id=$2
  UNION ALL
  SELECT p.parent_id,l.depth+1,l.path||p.parent_id FROM template_parents p
  JOIN linked l ON p.template_id=l.id WHERE p.tenant_id=$1 AND NOT p.parent_id=ANY(l.path)
), ranks AS (SELECT id,MAX(depth) AS depth FROM linked GROUP BY id)
SELECT i.key,i.kind,i.interval_s,i.params FROM items i LEFT JOIN ranks r ON r.id=i.template_id
WHERE i.tenant_id=$1 AND (r.id IS NOT NULL OR i.host_id=$2)
ORDER BY (i.host_id IS NOT NULL),COALESCE(r.depth,-1) DESC,i.created_at,i.id
"#;

#[derive(Clone, Deserialize)]
struct DeviceConfig {
    addr: String,
    version: String,
    #[serde(default)]
    community: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    auth: String,
    #[serde(default)]
    privacy: String,
    #[serde(default = "default_interval")]
    interval_s: u64,
    #[serde(default = "default_timeout")]
    timeout_s: u64,
}
fn default_interval() -> u64 {
    30
}
fn default_timeout() -> u64 {
    15
}

impl DeviceConfig {
    fn target(&self) -> Result<SnmpTarget, Error> {
        let _: std::net::SocketAddr = self.addr.parse()?;
        let version = match self.version.as_str() {
            "v2c" if !self.community.is_empty() => SnmpVersion::V2c {
                community: self.community.clone(),
            },
            "v3" if !self.user.is_empty() && !self.auth.is_empty() && !self.privacy.is_empty() => {
                SnmpVersion::V3 {
                    user: self.user.clone(),
                    auth: self.auth.clone(),
                    privacy: self.privacy.clone(),
                }
            }
            _ => return Err("invalid SNMP device credentials".into()),
        };
        Ok(SnmpTarget {
            addr: self.addr.clone(),
            version,
        })
    }
}

#[derive(Clone)]
struct Item {
    key: String,
    oid: String,
    walk: bool,
    interval: Duration,
    metric: Option<String>,
}
struct Device {
    tenant: Uuid,
    host: Uuid,
    name: String,
    fingerprint: String,
    config: DeviceConfig,
    items: Vec<Item>,
}

/// The server owns this task and aborts it on shutdown. JoinSet drops cancel
/// every child schedule; blocking socket workers retain their own permits.
pub(crate) fn spawn(state: ApiState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (Some(db), Some(secrets)) = (&state.db, &state.secrets) else {
            return;
        };
        let pool = Arc::new(TimeoutPool::new(DEFAULT_PERMITS));
        let mut children = JoinSet::new();
        let mut active: BTreeMap<(Uuid, Uuid), (String, tokio::task::AbortHandle)> =
            BTreeMap::new();
        let mut refresh = tokio::time::interval(Duration::from_secs(5));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            refresh.tick().await;
            let devices = match load_devices(db, secrets).await {
                Ok(devices) => devices,
                Err(err) => {
                    tracing::warn!(error=%err,"could not reload SNMP devices");
                    continue;
                }
            };
            active.retain(|key, (_, task)| {
                if devices.iter().any(|d| &(d.tenant, d.host) == key) {
                    true
                } else {
                    task.abort();
                    false
                }
            });
            for device in devices {
                let key = (device.tenant, device.host);
                if active.get(&key).is_some_and(|(fingerprint, task)| {
                    fingerprint == &device.fingerprint && !task.is_finished()
                }) {
                    continue;
                }
                if let Some((_, task)) = active.remove(&key) {
                    task.abort();
                }
                let fingerprint = device.fingerprint.clone();
                let store = state.store.clone();
                let pool = pool.clone();
                let task = children.spawn(async move {
                    run_device(device, Arc::new(BlockingPoller), pool, store).await;
                });
                active.insert(key, (fingerprint, task));
            }
            while children.try_join_next().is_some() {}
        }
    })
}

async fn load_devices(db: &Db, secrets: &SecretBox) -> Result<Vec<Device>, Error> {
    let rows=sqlx::query("SELECT s.tenant_id,s.host_id,s.config,h.name FROM host_snmp s JOIN hosts h ON h.tenant_id=s.tenant_id AND h.id=s.host_id").fetch_all(&db.pool).await?;
    let mut devices = Vec::new();
    for row in rows {
        let tenant: Uuid = row.try_get("tenant_id")?;
        let host: Uuid = row.try_get("host_id")?;
        let result: Result<Device, Error> = async {
            let encrypted: Value = row.try_get("config")?;
            let text = secrets.decrypt(
                encrypted["encrypted"]
                    .as_str()
                    .ok_or("missing encrypted SNMP configuration")?,
            )?;
            let config: DeviceConfig = serde_json::from_str(&text)?;
            config.target()?;
            let rows = sqlx::query(ITEMS_SQL)
                .bind(tenant)
                .bind(host)
                .fetch_all(&db.pool)
                .await?;
            let mut items = BTreeMap::new();
            let mut saw_snmp = false;
            let mut signature = format!("{}:{}", encrypted, row.try_get::<String, _>("name")?);
            for row in rows {
                let key: String = row.try_get("key")?;
                let kind: String = row.try_get("kind")?;
                let interval: i32 = row.try_get("interval_s")?;
                let params: Value = row.try_get("params")?;
                signature.push_str(&format!("{key}:{kind}:{interval}:{params}"));
                saw_snmp |= kind == "snmp";
                let item = if kind == "snmp" {
                    params["oid"].as_str().map(|oid| Item {
                        key,
                        oid: oid.into(),
                        walk: params["walk"].as_bool().unwrap_or(false),
                        interval: Duration::from_secs(interval.max(1) as u64),
                        metric: params["metric"].as_str().map(str::to_string),
                    })
                } else {
                    None
                };
                items.insert(row.try_get::<String, _>("key")?, item);
            }
            if !saw_snmp {
                for (key, oid, walk) in [
                    ("sysUpTime", "1.3.6.1.2.1.1.3.0", false),
                    ("ifTable", IF_TABLE, true),
                    ("ifXTable", IF_X_TABLE, true),
                ] {
                    items.insert(
                        key.into(),
                        Some(Item {
                            key: key.into(),
                            oid: oid.into(),
                            walk,
                            interval: Duration::from_secs(config.interval_s.clamp(1, 86400)),
                            metric: None,
                        }),
                    );
                }
            }
            Ok(Device {
                tenant,
                host,
                name: row.try_get("name")?,
                fingerprint: signature,
                config,
                items: items.into_values().flatten().collect(),
            })
        }
        .await;
        match result {
            Ok(device) => devices.push(device),
            Err(_) => tracing::warn!(host=%host,"invalid SNMP configuration; device skipped"),
        }
    }
    Ok(devices)
}

async fn run_device(
    device: Device,
    poller: Arc<dyn SnmpPoller>,
    pool: Arc<TimeoutPool>,
    store: Arc<dyn crate::MetricStore>,
) {
    let Ok(target) = device.config.target() else {
        return;
    };
    let mut due = vec![tokio::time::Instant::now(); device.items.len()];
    let mut names = BTreeMap::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let now = tokio::time::Instant::now();
        let mut rows = Vec::new();
        let mut polled = false;
        let mut successful = 0;
        for (index, item) in device.items.iter().enumerate() {
            if now < due[index] {
                continue;
            }
            due[index] = now + item.interval;
            polled = true;
            let result = pool
                .run(
                    Duration::from_secs(device.config.timeout_s.clamp(1, 60)),
                    async {
                        if item.walk {
                            poller.walk(&target, &item.oid).await
                        } else {
                            poller.get(&target, &item.oid).await.map(|v| vec![v])
                        }
                    },
                )
                .await;
            match result {
                Ok(Ok(values)) => {
                    successful += 1;
                    rows.extend(values.into_iter().map(|value| (item.clone(), value)));
                }
                _ => {
                    tracing::warn!(host=%device.host,item=%item.key,"SNMP poll failed");
                }
            }
        }
        if !polled {
            continue;
        }
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let labels = vec![
            ("tenant".into(), device.tenant.to_string()),
            ("host".into(), device.name.clone()),
            ("host_id".into(), device.host.to_string()),
        ];
        let mut samples = map_samples(&rows, &mut names, &labels, timestamp_ms);
        samples.push(LabelledSample {
            name: "snmp_up".into(),
            labels,
            value: if successful > 0 { 1.0 } else { 0.0 },
            timestamp_ms,
        });
        if let Err(err) = store.write(samples).await {
            tracing::warn!(host=%device.host,error=%err,"could not store SNMP samples");
        }
    }
}

fn column<'a>(oid: &'a str, root: &str, column: u32) -> Option<&'a str> {
    oid.strip_prefix(&format!("{root}.{column}."))
}

fn map_samples(
    rows: &[(Item, SnmpVar)],
    names: &mut BTreeMap<String, String>,
    labels: &[(String, String)],
    timestamp_ms: i64,
) -> Vec<LabelledSample> {
    // ifName wins over ifDescr regardless of walk order.
    for root in [(IF_TABLE, 2), (IF_X_TABLE, 1)] {
        for (_, row) in rows {
            if let Some(index) = column(&row.oid, root.0, root.1) {
                names.insert(index.into(), row.value.clone());
            }
        }
    }
    let mut samples = BTreeMap::new();
    for (item, row) in rows {
        let Ok(value) = row.value.parse::<f64>() else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        let mut sample_labels = labels.to_vec();
        let mut metric = None;
        for (root, col, name) in [
            (IF_TABLE, 8, "snmp_if_oper_status"),
            (IF_TABLE, 10, "snmp_if_in_octets_total"),
            (IF_TABLE, 16, "snmp_if_out_octets_total"),
            (IF_X_TABLE, 6, "snmp_if_in_octets_total"),
            (IF_X_TABLE, 10, "snmp_if_out_octets_total"),
        ] {
            if let Some(index) = column(&row.oid, root, col) {
                sample_labels.push(("ifindex".into(), index.into()));
                sample_labels.push((
                    "ifname".into(),
                    names.get(index).cloned().unwrap_or_else(|| index.into()),
                ));
                metric = Some(name.to_string());
                break;
            }
        }
        let metric = metric.or_else(|| item.metric.clone()).unwrap_or_else(|| {
            if row.oid == "1.3.6.1.2.1.1.3.0" {
                "snmp_sys_uptime_ticks".into()
            } else if row.oid == "1.3.6.1.2.1.33.1.2.1.0" {
                "snmp_ups_battery_status".into()
            } else {
                sample_labels.push(("oid".into(), row.oid.clone()));
                "snmp_oid_value".into()
            }
        });
        let key = format!("{metric}{sample_labels:?}");
        // Process 64-bit counters after 32-bit rows, so devices exposing
        // both do not emit duplicate series or lose the wider counter.
        let high = row.oid.starts_with(IF_X_TABLE);
        if !samples.contains_key(&key) || high {
            samples.insert(
                key,
                LabelledSample {
                    name: metric,
                    labels: sample_labels,
                    value,
                    timestamp_ms,
                },
            );
        }
    }
    samples.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct MixedPoller;
    #[async_trait]
    impl SnmpPoller for MixedPoller {
        async fn get(
            &self,
            target: &SnmpTarget,
            oid: &str,
        ) -> Result<SnmpVar, super::super::snmp::PollError> {
            if target.addr.ends_with(":1") {
                std::future::pending::<()>().await;
            }
            Ok(SnmpVar {
                oid: oid.into(),
                value: "123".into(),
            })
        }
        async fn walk(
            &self,
            target: &SnmpTarget,
            oid: &str,
        ) -> Result<Vec<SnmpVar>, super::super::snmp::PollError> {
            self.get(target, oid).await.map(|v| vec![v])
        }
    }

    #[tokio::test]
    async fn snmp_slow_device_does_not_block_other_device_samples() {
        let pool = Arc::new(TimeoutPool::new(2));
        let store = Arc::new(crate::MemoryStore::new());
        let device = |name: &str, port: u16| Device {
            tenant: Uuid::new_v4(),
            host: Uuid::new_v4(),
            name: name.into(),
            fingerprint: String::new(),
            config: DeviceConfig {
                addr: format!("127.0.0.1:{port}"),
                version: "v2c".into(),
                community: "fixture".into(),
                user: String::new(),
                auth: String::new(),
                privacy: String::new(),
                interval_s: 30,
                timeout_s: 1,
            },
            items: vec![Item {
                key: "up".into(),
                oid: "1.3.6.1.2.1.1.3.0".into(),
                walk: false,
                interval: Duration::from_secs(30),
                metric: None,
            }],
        };
        let slow = tokio::spawn(run_device(
            device("slow", 1),
            Arc::new(MixedPoller),
            pool.clone(),
            store.clone(),
        ));
        let fast = tokio::spawn(run_device(
            device("fast", 2),
            Arc::new(MixedPoller),
            pool,
            store.clone(),
        ));
        tokio::time::timeout(Duration::from_millis(500), async {
            while store.len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        slow.abort();
        fast.abort();
        let _ = slow.await;
        let _ = fast.await;
    }
    #[test]
    fn snmp_interface_names_and_64bit_counters_form_graphable_series() {
        let item = Item {
            key: "if".into(),
            oid: IF_TABLE.into(),
            walk: true,
            interval: Duration::from_secs(30),
            metric: None,
        };
        let rows = [
            (format!("{IF_TABLE}.2.7"), "description"),
            (format!("{IF_X_TABLE}.1.7"), "uplink"),
            (format!("{IF_TABLE}.10.7"), "42"),
            (format!("{IF_X_TABLE}.6.7"), "4294967300"),
            (format!("{IF_TABLE}.8.7"), "1"),
        ]
        .into_iter()
        .map(|(oid, value)| {
            (
                item.clone(),
                SnmpVar {
                    oid,
                    value: value.into(),
                },
            )
        })
        .collect::<Vec<_>>();
        let samples = map_samples(
            &rows,
            &mut BTreeMap::new(),
            &[("host".into(), "switch".into())],
            123,
        );
        let counter = samples
            .iter()
            .find(|s| s.name == "snmp_if_in_octets_total")
            .unwrap();
        assert_eq!(counter.value, 4294967300.0);
        assert!(counter.labels.contains(&("ifname".into(), "uplink".into())));
        assert_eq!(
            samples
                .iter()
                .filter(|s| s.name == "snmp_if_in_octets_total")
                .count(),
            1
        );
    }
}
