use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Action {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub media_type_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewAction {
    pub name: String,
    pub media_type_id: Option<Uuid>,
}

impl Db {
    pub async fn list_actions(&self, tenant: &TenantId) -> Result<Vec<Action>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, name, media_type_id, created_at, updated_at
             FROM actions
             WHERE tenant_id = $1
             ORDER BY name",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_action(
        &self,
        tenant: &TenantId,
        new: NewAction,
    ) -> Result<Action, ServerError> {
        sqlx::query_as(
            "INSERT INTO actions (tenant_id, name, media_type_id)
             VALUES ($1, $2, $3)
             RETURNING id, tenant_id, name, media_type_id, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.name)
        .bind(new.media_type_id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
