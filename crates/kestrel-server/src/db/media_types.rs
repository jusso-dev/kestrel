use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MediaType {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewMediaType {
    pub name: String,
    pub kind: String,
    pub config: Value,
}

impl Db {
    pub async fn list_media_types(&self, tenant: &TenantId) -> Result<Vec<MediaType>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, name, kind, config, created_at, updated_at
             FROM media_types
             WHERE tenant_id = $1
             ORDER BY name",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_media_type(
        &self,
        tenant: &TenantId,
        new: NewMediaType,
    ) -> Result<MediaType, ServerError> {
        sqlx::query_as(
            "INSERT INTO media_types (tenant_id, name, kind, config)
             VALUES ($1, $2, $3, $4)
             RETURNING id, tenant_id, name, kind, config, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.name)
        .bind(new.kind)
        .bind(new.config)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
