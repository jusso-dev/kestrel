use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HostGroup {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewHostGroup {
    pub name: String,
}

impl Db {
    pub async fn list_host_groups(&self, tenant: &TenantId) -> Result<Vec<HostGroup>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, name, created_at, updated_at
             FROM host_groups
             WHERE tenant_id = $1
             ORDER BY name",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_host_group(
        &self,
        tenant: &TenantId,
        new: NewHostGroup,
    ) -> Result<HostGroup, ServerError> {
        sqlx::query_as(
            "INSERT INTO host_groups (tenant_id, name)
             VALUES ($1, $2)
             RETURNING id, tenant_id, name, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.name)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
