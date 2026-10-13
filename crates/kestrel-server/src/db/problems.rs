use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Problem {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub trigger_id: Uuid,
    pub host_id: Option<Uuid>,
    pub status: String,
    pub severity: String,
    pub opened_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewProblem {
    pub trigger_id: Uuid,
    pub host_id: Option<Uuid>,
    pub status: String,
    pub severity: String,
}

impl Db {
    pub async fn list_problems(&self, tenant: &TenantId) -> Result<Vec<Problem>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, trigger_id, host_id, status, severity, opened_at, resolved_at,
                    acknowledged_at, created_at, updated_at
             FROM problems
             WHERE tenant_id = $1
             ORDER BY opened_at",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_problem(
        &self,
        tenant: &TenantId,
        new: NewProblem,
    ) -> Result<Problem, ServerError> {
        sqlx::query_as(
            "INSERT INTO problems (tenant_id, trigger_id, host_id, status, severity)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, tenant_id, trigger_id, host_id, status, severity, opened_at, resolved_at,
                       acknowledged_at, created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.trigger_id)
        .bind(new.host_id)
        .bind(new.status)
        .bind(new.severity)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
