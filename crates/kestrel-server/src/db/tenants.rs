use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Db {
    pub async fn get_tenant(&self, tenant: &TenantId) -> Result<Option<Tenant>, ServerError> {
        sqlx::query_as("SELECT id, name, created_at, updated_at FROM tenants WHERE id = $1")
            .bind(tenant.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)
    }

    pub async fn insert_tenant(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Tenant, ServerError> {
        sqlx::query_as(
            "INSERT INTO tenants (id, name)
             VALUES ($1, $2)
             RETURNING id, name, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
