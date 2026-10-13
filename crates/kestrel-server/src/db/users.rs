use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub host_group_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewUser {
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub host_group_id: Option<Uuid>,
}

impl Db {
    pub async fn list_users(&self, tenant: &TenantId) -> Result<Vec<User>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, email, password_hash, role, host_group_id, created_at, updated_at
             FROM users
             WHERE tenant_id = $1
             ORDER BY email",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_user(&self, tenant: &TenantId, new: NewUser) -> Result<User, ServerError> {
        sqlx::query_as(
            "INSERT INTO users (tenant_id, email, password_hash, role, host_group_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, tenant_id, email, password_hash, role, host_group_id, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.email)
        .bind(new.password_hash)
        .bind(new.role)
        .bind(new.host_group_id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
