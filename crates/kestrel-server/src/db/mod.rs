//! PostgreSQL repositories. Every tenant-owned query takes a [`TenantId`].

mod actions;
mod agents;
mod api_tokens;
mod audit;
mod host_groups;
mod hosts;
mod ingest_runtime;
mod items;
mod maintenances;
mod media_types;
mod notification_jobs;
mod problems;
mod templates;
mod tenants;
mod triggers;
mod users;

pub use actions::{Action, NewAction};
pub use agents::{Agent, NewAgent};
pub use api_tokens::{ApiToken, NewApiToken};
pub use audit::{AuditEntry, NewAuditEntry};
pub use host_groups::{HostGroup, NewHostGroup};
pub use hosts::{Host, HostFilter, NewHost};
pub(crate) use ingest_runtime::HOST_CONFLICT;
pub use items::{Item, NewItem};
pub use maintenances::{Maintenance, NewMaintenance};
pub use media_types::{MediaType, NewMediaType};
pub use notification_jobs::{NewNotificationJob, NotificationJob};
pub use problems::{NewProblem, Problem};
pub use templates::{NewTemplate, Template};
pub use tenants::Tenant;
pub use triggers::{NewTrigger, Trigger};
pub use users::{NewUser, User};

use crate::ServerError;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// Tenant that scopes a repository call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub Uuid);

impl TenantId {
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Seeded `default` tenant. Matches the enrolment store's tenant id.
    pub const fn default_tenant() -> Self {
        Self(crate::store::DEFAULT_TENANT_ID)
    }
}

/// Connection pool and the applied migrations.
#[derive(Clone)]
pub struct Db {
    pub(crate) pool: PgPool,
    pub(crate) log_retention_days: i32,
}

impl Db {
    /// Connect and apply migrations.
    pub async fn connect(database_url: &str) -> Result<Self, ServerError> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|err| ServerError::new(format!("database connection failed: {err}")))?;
        Self::from_pool(pool).await
    }

    /// Apply migrations to an existing pool.
    pub async fn from_pool(pool: PgPool) -> Result<Self, ServerError> {
        let db = Self {
            pool,
            log_retention_days: 7,
        };
        db.migrate().await?;
        Ok(db)
    }

    /// Apply migrations. A second call is a no-op once they are recorded.
    pub async fn migrate(&self) -> Result<(), ServerError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|err| ServerError::new(format!("database migration failed: {err}")))?;
        Ok(())
    }
}

pub(crate) fn db_err(err: sqlx::Error) -> ServerError {
    ServerError::new(format!("database: {err}"))
}

#[cfg(test)]
mod tests;
