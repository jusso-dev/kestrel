use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Maintenance {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub host_group_id: Option<Uuid>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub rrule: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewMaintenance {
    pub name: String,
    pub host_group_id: Option<Uuid>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub rrule: Option<String>,
}

impl Db {
    pub async fn list_maintenances(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<Maintenance>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, name, host_group_id, starts_at, ends_at, rrule, created_at, updated_at
             FROM maintenances
             WHERE tenant_id = $1
             ORDER BY starts_at",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_maintenance(
        &self,
        tenant: &TenantId,
        new: NewMaintenance,
    ) -> Result<Maintenance, ServerError> {
        sqlx::query_as(
            "INSERT INTO maintenances (tenant_id, name, host_group_id, starts_at, ends_at, rrule)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, tenant_id, name, host_group_id, starts_at, ends_at, rrule, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.name)
        .bind(new.host_group_id)
        .bind(new.starts_at)
        .bind(new.ends_at)
        .bind(new.rrule)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
