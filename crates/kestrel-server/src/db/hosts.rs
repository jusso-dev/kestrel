use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Host {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub host_group_id: Option<Uuid>,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Default, Clone)]
pub struct HostFilter {
    pub host_group_id: Option<Uuid>,
    pub name: Option<String>,
}

pub struct NewHost {
    pub host_group_id: Option<Uuid>,
    pub name: String,
}

impl Db {
    pub async fn list_hosts(
        &self,
        tenant: &TenantId,
        filter: HostFilter,
    ) -> Result<Vec<Host>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, host_group_id, name, created_at, updated_at
             FROM hosts
             WHERE tenant_id = $1
               AND ($2::uuid IS NULL OR host_group_id = $2)
               AND ($3::text IS NULL OR name = $3)
             ORDER BY name",
        )
        .bind(tenant.0)
        .bind(filter.host_group_id)
        .bind(filter.name)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn get_host(&self, tenant: &TenantId, id: Uuid) -> Result<Option<Host>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, host_group_id, name, created_at, updated_at
             FROM hosts
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.0)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_host(&self, tenant: &TenantId, new: NewHost) -> Result<Host, ServerError> {
        sqlx::query_as(
            "INSERT INTO hosts (tenant_id, host_group_id, name)
             VALUES ($1, $2, $3)
             RETURNING id, tenant_id, host_group_id, name, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.host_group_id)
        .bind(new.name)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
