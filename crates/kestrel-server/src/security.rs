//! Replay certificate lifecycle events atomically with forwarding. The local
//! directory outbox also records operator CLI changes while the server is down.
use crate::{api::ApiState, store::AgentSecurityEvent};
use serde_json::json;

pub(crate) fn spawn(state: ApiState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if drain(&state).await.is_err() {
                tracing::warn!("agent security events retained for retry");
            }
        }
    })
}

async fn record(
    state: &ApiState,
    event: &AgentSecurityEvent,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = state.db.as_ref().ok_or("database unavailable")?;
    let mut tx = db.pool.begin().await?;
    let inserted:Option<uuid::Uuid>=sqlx::query_scalar("INSERT INTO agent_security_events (id,tenant_id,agent_id,kind,detail) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id").bind(event.id).bind(event.tenant_id).bind(event.agent_id).bind(&event.kind).bind(json!({"hostname":event.hostname,"observed_at":event.observed_at})).fetch_optional(&mut *tx).await?;
    if inserted.is_some() {
        sqlx::query("INSERT INTO audit_log (tenant_id,action,target,detail) VALUES ($1,$2,$3,$4)")
            .bind(event.tenant_id)
            .bind(&event.kind)
            .bind(event.agent_id.to_string())
            .bind(json!({"hostname":event.hostname,"event_id":event.id}))
            .execute(&mut *tx)
            .await?;
        let mut finding = crate::forward::detection_finding(
            &event.kind,
            &event.hostname,
            "problem",
            if event.kind.ends_with("rejected") {
                "medium"
            } else {
                "informational"
            },
        );
        finding["finding_info"]["uid"] = json!(event.id);
        finding["time"] =
            json!(chrono::DateTime::parse_from_rfc3339(&event.observed_at)?.timestamp_millis());
        crate::runtime::enqueue_forward(&mut tx, event.tenant_id, "agent_security", &finding)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn drain(
    state: &ApiState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (Some(_), Some(directory)) = (&state.db, &state.directory) else {
        return Ok(());
    };
    for event in directory.pending_security_events()? {
        record(state, &event).await?;
        directory.ack_security_event(event.id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::MemoryCatalog,
        db::Db,
        store::{Directory, EnrolCommit},
        MemoryStore,
    };
    use std::sync::Arc;
    #[tokio::test]
    async fn security_events_survive_offline_cli_revoke_and_replay_once() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let db = Db::connect(&url).await.unwrap();
        let path = std::env::temp_dir().join(format!("kestrel-security-{}", uuid::Uuid::new_v4()));
        let directory = Arc::new(Directory::open(&path).unwrap());
        let token = directory
            .create_token(None, std::time::Duration::from_secs(60))
            .unwrap();
        let agent = uuid::Uuid::new_v4();
        directory
            .commit_enrol(EnrolCommit {
                token,
                agent_id: agent,
                hostname: "security-test".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                cert_serial: "01".into(),
                cert_not_after: "2030-01-01T00:00:00Z".into(),
            })
            .unwrap();
        directory
            .commit_renew(agent, "02", "2030-02-01T00:00:00Z")
            .unwrap();
        crate::admin::revoke_agent(&path, agent).unwrap();
        directory.record_security_rejection(agent).unwrap();
        let events = directory.pending_security_events().unwrap();
        assert_eq!(events.len(), 4);
        let mut state = ApiState::new(Arc::new(MemoryCatalog::new()), Arc::new(MemoryStore::new()));
        state.db = Some(db.clone());
        state.directory = Some(Arc::clone(&directory));
        record(&state, &events[0]).await.unwrap();
        record(&state, &events[0]).await.unwrap();
        drain(&state).await.unwrap();
        assert!(directory.pending_security_events().unwrap().is_empty());
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM agent_security_events WHERE agent_id=$1")
                .bind(agent)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(count, 4);
        let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE target=$1")
            .bind(agent.to_string())
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(audits, 4);
        std::fs::remove_dir_all(path).unwrap();
    }
}
