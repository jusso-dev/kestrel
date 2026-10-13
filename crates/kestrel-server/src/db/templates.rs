use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Template {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewTemplate {
    pub name: String,
    pub description: String,
}

impl Db {
    pub async fn list_templates(&self, tenant: &TenantId) -> Result<Vec<Template>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, name, description, created_at, updated_at
             FROM templates
             WHERE tenant_id = $1
             ORDER BY name",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_template(
        &self,
        tenant: &TenantId,
        new: NewTemplate,
    ) -> Result<Template, ServerError> {
        sqlx::query_as(
            "INSERT INTO templates (tenant_id, name, description)
             VALUES ($1, $2, $3)
             RETURNING id, tenant_id, name, description, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.name)
        .bind(new.description)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
