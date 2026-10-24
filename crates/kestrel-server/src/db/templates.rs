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

/// Template-level triggers (template set, no host) paired with every host that
/// inherits them through links and parent templates. `$2` limits it to a host.
const WANTED_COPIES: &str = "WITH RECURSIVE linked(host_id,id,path) AS (SELECT host_id,template_id,ARRAY[template_id] FROM template_links WHERE tenant_id=$1 AND ($2::uuid IS NULL OR host_id=$2) UNION ALL SELECT l.host_id,p.parent_id,l.path||p.parent_id FROM template_parents p JOIN linked l ON p.template_id=l.id WHERE p.tenant_id=$1 AND NOT p.parent_id=ANY(l.path)), wanted AS (SELECT DISTINCT l.host_id,t.id AS source_id FROM linked l JOIN triggers t ON t.tenant_id=$1 AND t.template_id=l.id AND t.host_id IS NULL)";

/// Materialise per-host copies of inherited template triggers, keyed on the
/// source trigger, so the evaluator scopes each to its host. Copies whose
/// source is no longer inherited are disabled, not deleted, so problem history
/// keeps its trigger. A `host` of `None` reconciles every host in the tenant.
pub(crate) async fn reconcile_template_triggers(
    conn: &mut sqlx::PgConnection,
    tenant: Uuid,
    host: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("{WANTED_COPIES} INSERT INTO triggers (tenant_id,host_id,template_id,source_trigger_id,name,expression,severity,for_seconds,recovery_expr,labels,interval_s,recover_for,enabled) SELECT t.tenant_id,w.host_id,t.template_id,t.id,t.name,t.expression,t.severity,t.for_seconds,t.recovery_expr,t.labels,t.interval_s,t.recover_for,t.enabled FROM wanted w JOIN triggers t ON t.tenant_id=$1 AND t.id=w.source_id ON CONFLICT (tenant_id,host_id,source_trigger_id) WHERE source_trigger_id IS NOT NULL DO UPDATE SET template_id=EXCLUDED.template_id,name=EXCLUDED.name,expression=EXCLUDED.expression,severity=EXCLUDED.severity,for_seconds=EXCLUDED.for_seconds,recovery_expr=EXCLUDED.recovery_expr,labels=EXCLUDED.labels,interval_s=EXCLUDED.interval_s,recover_for=EXCLUDED.recover_for,enabled=EXCLUDED.enabled WHERE (triggers.template_id,triggers.name,triggers.expression,triggers.severity,triggers.for_seconds,triggers.recovery_expr,triggers.labels,triggers.interval_s,triggers.recover_for,triggers.enabled) IS DISTINCT FROM (EXCLUDED.template_id,EXCLUDED.name,EXCLUDED.expression,EXCLUDED.severity,EXCLUDED.for_seconds,EXCLUDED.recovery_expr,EXCLUDED.labels,EXCLUDED.interval_s,EXCLUDED.recover_for,EXCLUDED.enabled)"))
        .bind(tenant)
        .bind(host)
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!("{WANTED_COPIES} UPDATE triggers c SET enabled=false WHERE c.tenant_id=$1 AND ($2::uuid IS NULL OR c.host_id=$2) AND c.source_trigger_id IS NOT NULL AND c.enabled AND NOT EXISTS (SELECT 1 FROM wanted w WHERE w.host_id=c.host_id AND w.source_id=c.source_trigger_id)"))
        .bind(tenant)
        .bind(host)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
