//! Operator commands used by the `kestrel` CLI.

use crate::store::Directory;
use crate::ServerError;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

/// Create a one-time enrolment token and return the secret once.
pub fn create_token(
    data_dir: &Path,
    group: Option<String>,
    ttl: Duration,
) -> Result<String, ServerError> {
    let store = Directory::open(data_dir)?;
    let token = store.create_token(group, ttl)?;
    tracing::info!(data_dir = %data_dir.display(), "enrolment token created");
    Ok(token)
}

/// Mark an agent revoked. The next ingest or renew is rejected.
pub fn revoke_agent(data_dir: &Path, agent_id: Uuid) -> Result<(), ServerError> {
    let store = Directory::open(data_dir)?;
    store.revoke(agent_id)?;
    tracing::info!(%agent_id, "agent revoked");
    Ok(())
}
