use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Agent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub host_id: Option<Uuid>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cert_serial: String,
    pub cert_not_after: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewAgent {
    pub id: Option<Uuid>,
    pub host_id: Option<Uuid>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cert_serial: String,
    pub cert_not_after: Option<DateTime<Utc>>,
}

impl Db {
    pub async fn list_agents(&self, tenant: &TenantId) -> Result<Vec<Agent>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, host_id, hostname, os, arch, cert_serial, cert_not_after,
                    revoked_at, created_at, updated_at
             FROM agents
             WHERE tenant_id = $1
             ORDER BY hostname",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_agent(
        &self,
        tenant: &TenantId,
        new: NewAgent,
    ) -> Result<Agent, ServerError> {
        sqlx::query_as(
            "INSERT INTO agents
                (id, tenant_id, host_id, hostname, os, arch, cert_serial, cert_not_after)
             VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, tenant_id, host_id, hostname, os, arch, cert_serial, cert_not_after,
                       revoked_at, created_at, updated_at",
        )
        .bind(new.id)
        .bind(tenant.0)
        .bind(new.host_id)
        .bind(new.hostname)
        .bind(new.os)
        .bind(new.arch)
        .bind(new.cert_serial)
        .bind(new.cert_not_after)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn revoke_agent(&self, tenant: &TenantId, id: Uuid) -> Result<Agent, ServerError> {
        sqlx::query_as(
            "UPDATE agents
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE tenant_id = $1 AND id = $2
             RETURNING id, tenant_id, host_id, hostname, os, arch, cert_serial, cert_not_after,
                       revoked_at, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ServerError::new("agent not found"))
    }
}
