use super::{db_err, Db, TenantId};
use crate::ServerError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NotificationJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub problem_id: Option<Uuid>,
    pub media_type_id: Uuid,
    pub status: String,
    pub payload: Value,
    pub attempts: i32,
    pub run_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewNotificationJob {
    pub problem_id: Option<Uuid>,
    pub media_type_id: Uuid,
    pub payload: Value,
}

impl Db {
    pub async fn list_notification_jobs(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<NotificationJob>, ServerError> {
        sqlx::query_as(
            "SELECT id, tenant_id, problem_id, media_type_id, status, payload, attempts, run_after,
                    created_at, updated_at
             FROM notification_jobs
             WHERE tenant_id = $1
             ORDER BY run_after",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn insert_notification_job(
        &self,
        tenant: &TenantId,
        new: NewNotificationJob,
    ) -> Result<NotificationJob, ServerError> {
        sqlx::query_as(
            "INSERT INTO notification_jobs (tenant_id, problem_id, media_type_id, status, payload)
             VALUES ($1, $2, $3, 'pending', $4)
             RETURNING id, tenant_id, problem_id, media_type_id, status, payload, attempts, run_after,
                       created_at, updated_at",
        )
        .bind(tenant.0)
        .bind(new.problem_id)
        .bind(new.media_type_id)
        .bind(new.payload)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)
    }
}
