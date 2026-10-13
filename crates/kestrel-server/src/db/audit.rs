use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewAuditEntry {
    pub user_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    pub detail: Value,
}

impl Db {
    pub async fn list_audit_log(&self, tenant: &TenantId) -> Result<Vec<AuditEntry>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, user_id, action, target, detail, created_at, updated_at
             FROM audit_log
             WHERE tenant_id = $1
             ORDER BY created_at",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_audit(
        &self,
        tenant: &TenantId,
        new: NewAuditEntry,
    ) -> Result<AuditEntry, ServerError> {
        sqlx::query_as(
            "INSERT INTO audit_log (tenant_id, user_id, action, target, detail)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, tenant_id, user_id, action, target, detail, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.user_id)
        .bind(new.action)
        .bind(new.target)
        .bind(new.detail)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
