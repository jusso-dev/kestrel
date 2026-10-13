use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Trigger {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub template_id: Option<Uuid>,
    pub host_id: Option<Uuid>,
    pub name: String,
    pub expression: String,
    pub severity: String,
    pub for_seconds: i32,
    pub recovery_expr: Option<String>,
    pub labels: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewTrigger {
    pub template_id: Option<Uuid>,
    pub host_id: Option<Uuid>,
    pub name: String,
    pub expression: String,
    pub severity: String,
    pub for_seconds: i32,
    pub recovery_expr: Option<String>,
    pub labels: Value,
}

impl Db {
    pub async fn list_triggers(&self, tenant: &TenantId) -> Result<Vec<Trigger>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, template_id, host_id, name, expression, severity, for_seconds,
                    recovery_expr, labels, created_at, updated_at
             FROM triggers
             WHERE tenant_id = $1
             ORDER BY name",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_trigger(
        &self,
        tenant: &TenantId,
        new: NewTrigger,
    ) -> Result<Trigger, ServerError> {
        sqlx::query_as(
            "INSERT INTO triggers
                (tenant_id, template_id, host_id, name, expression, severity, for_seconds,
                 recovery_expr, labels)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             RETURNING id, tenant_id, template_id, host_id, name, expression, severity, for_seconds,
                       recovery_expr, labels, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.template_id)
        .bind(new.host_id)
        .bind(new.name)
        .bind(new.expression)
        .bind(new.severity)
        .bind(new.for_seconds)
        .bind(new.recovery_expr)
        .bind(new.labels)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
