use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewApiToken {
    pub user_id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Db {
    pub async fn list_api_tokens(&self, tenant: &TenantId) -> Result<Vec<ApiToken>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, user_id, name, token_hash, expires_at, created_at, updated_at
             FROM api_tokens
             WHERE tenant_id = $1
             ORDER BY name",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_api_token(
        &self,
        tenant: &TenantId,
        new: NewApiToken,
    ) -> Result<ApiToken, ServerError> {
        sqlx::query_as(
            "INSERT INTO api_tokens (tenant_id, user_id, name, token_hash, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, tenant_id, user_id, name, token_hash, expires_at, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.user_id)
        .bind(new.name)
        .bind(new.token_hash)
        .bind(new.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
