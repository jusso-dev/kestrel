//! Trigger evaluation. The state machine lives in [`state`].

mod state;

pub use state::{step, EventKind, Fired, Transition, TriggerState};

use crate::store::{MetricStore, Series};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use uuid::Uuid;

pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15);
pub const MIN_INTERVAL_S: u32 = 15;
/// Instant queries only look back a few minutes, so a bare gauge vanishes
/// before the delay elapses. The range keeps a silent host firing for a day.
pub const AGENT_UNREACHABLE_EXPR: &str =
    "time() - max_over_time(kestrel_agent_last_seen_timestamp[24h]) > 180";

#[derive(Debug, Clone)]
pub struct TriggerDef {
    pub id: Uuid,
    pub name: String,
    pub expression: String,
    pub recovery_expr: Option<String>,
    pub for_seconds: i64,
    pub recover_for: i64,
    pub severity: String,
    pub interval_s: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceEvent {
    pub trigger_id: Uuid,
    pub instance: String,
    pub fired: Fired,
}

pub fn instance_hash(labels: &[(String, String)]) -> String {
    let mut labels = labels.to_vec();
    labels.sort();
    let mut hasher = Sha256::new();
    for (name, value) in labels {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    data_encoding::HEXLOWER.encode(hasher.finalize().as_slice())
}

pub async fn evaluate_trigger(
    store: &dyn MetricStore,
    trigger: &TriggerDef,
    states: &BTreeMap<String, TriggerState>,
    now: i64,
    new_id: impl Fn() -> Uuid,
) -> Result<(BTreeMap<String, TriggerState>, Vec<InstanceEvent>), crate::ServerError> {
    let firing = store.query(&trigger.expression, now).await?;
    let recovering = match &trigger.recovery_expr {
        Some(expr) if !expr.is_empty() => store.query(expr, now).await?,
        _ => Vec::new(),
    };
    let mut firing_keys = series_keys(&firing);
    for key in series_keys(&recovering).into_keys() {
        firing_keys.remove(&key);
    }
    let mut next = BTreeMap::new();
    let mut events = Vec::new();
    let mut seen = BTreeMap::new();
    for key in firing_keys.keys() {
        seen.insert(key.clone(), true);
    }
    for key in states.keys() {
        seen.entry(key.clone()).or_insert(false);
    }
    for (key, active) in seen {
        let previous = states.get(&key).cloned().unwrap_or(TriggerState::Ok);
        let transition = step(
            &previous,
            active,
            now,
            trigger.for_seconds,
            trigger.recover_for,
            new_id(),
        );
        if let Some(fired) = transition.event.clone() {
            events.push(InstanceEvent {
                trigger_id: trigger.id,
                instance: key.clone(),
                fired,
            });
        }
        if transition.state != TriggerState::Ok {
            next.insert(key, transition.state);
        }
    }
    Ok((next, events))
}

fn series_keys(series: &[Series]) -> BTreeMap<String, Vec<(String, String)>> {
    let mut keys = BTreeMap::new();
    for item in series {
        let labels: Vec<(String, String)> = item
            .labels
            .iter()
            .filter(|(name, _)| name != "__name__")
            .cloned()
            .collect();
        keys.insert(instance_hash(&labels), labels);
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{LabelledSample, MemoryStore};
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct ScriptStore {
        rounds: Mutex<Vec<Vec<Series>>>,
    }

    #[async_trait]
    impl MetricStore for ScriptStore {
        async fn write(&self, _samples: Vec<LabelledSample>) -> Result<(), crate::ServerError> {
            Ok(())
        }
        async fn query(&self, _promql: &str, _at: i64) -> Result<Vec<Series>, crate::ServerError> {
            let mut rounds = self.rounds.lock().unwrap_or_else(|err| err.into_inner());
            Ok(if rounds.is_empty() {
                Vec::new()
            } else {
                rounds.remove(0)
            })
        }
        async fn query_range(
            &self,
            _promql: &str,
            _start: i64,
            _end: i64,
            _step_s: u32,
        ) -> Result<Vec<Series>, crate::ServerError> {
            Ok(Vec::new())
        }
    }

    fn series() -> Series {
        Series {
            labels: vec![
                ("__name__".to_string(), "up".to_string()),
                ("host".to_string(), "web".to_string()),
            ],
            points: vec![(1, 1.0)],
        }
    }

    #[tokio::test]
    async fn rules_evaluator_opens_once_and_keeps_identity_across_restart() {
        let trigger = TriggerDef {
            id: Uuid::from_u128(3),
            name: "disk".to_string(),
            expression: "up > 0".to_string(),
            recovery_expr: None,
            for_seconds: 0,
            recover_for: 0,
            severity: "high".to_string(),
            interval_s: 15,
        };
        let store = ScriptStore {
            rounds: Mutex::new(vec![vec![series()], vec![series()]]),
        };
        let (states, events) =
            evaluate_trigger(&store, &trigger, &BTreeMap::new(), 10, Uuid::new_v4)
                .await
                .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fired.kind, EventKind::Opened);
        let (states, events) = evaluate_trigger(&store, &trigger, &states, 20, Uuid::new_v4)
            .await
            .unwrap();
        assert!(events.is_empty(), "restart must not open a second problem");
        assert_eq!(states.len(), 1);
        let memory = MemoryStore::new();
        memory
            .write(vec![LabelledSample {
                name: "kestrel_agent_last_seen_timestamp".to_string(),
                labels: vec![("host".to_string(), "web".to_string())],
                value: 1_000.0,
                timestamp_ms: 1_300_000,
            }])
            .await
            .unwrap();
        let stale = memory.query(AGENT_UNREACHABLE_EXPR, 1_300).await.unwrap();
        assert_eq!(stale.len(), 1);
    }
}
