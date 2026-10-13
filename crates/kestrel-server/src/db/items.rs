use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Item {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub template_id: Uuid,
    pub key: String,
    pub kind: String,
    pub interval_s: i32,
    pub params: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewItem {
    pub template_id: Uuid,
    pub key: String,
    pub kind: String,
    pub interval_s: i32,
    pub params: Value,
}

impl Db {
    pub async fn list_items(&self, tenant: &TenantId) -> Result<Vec<Item>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, template_id, key, kind, interval_s, params, created_at, updated_at
             FROM items
             WHERE tenant_id = $1
             ORDER BY key",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_item(&self, tenant: &TenantId, new: NewItem) -> Result<Item, ServerError> {
        sqlx::query_as(
            "INSERT INTO items (tenant_id, template_id, key, kind, interval_s, params)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, tenant_id, template_id, key, kind, interval_s, params, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.template_id)
        .bind(new.key)
        .bind(new.kind)
        .bind(new.interval_s)
        .bind(new.params)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
