use super::{
    Db, HostFilter, NewAction, NewAgent, NewApiToken, NewAuditEntry, NewHost, NewHostGroup,
    NewItem, NewMaintenance, NewMediaType, NewNotificationJob, NewProblem, NewTemplate, NewTrigger,
    NewUser, TenantId,
};
use chrono::{Duration, Utc};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use uuid::Uuid;

const TENANT_TABLES: &[&str] = &[
    "users",
    "api_tokens",
    "host_groups",
    "hosts",
    "agents",
    "templates",
    "items",
    "triggers",
    "problems",
    "actions",
    "media_types",
    "notification_jobs",
    "maintenances",
    "audit_log",
];

#[test]
fn migration_sql_declares_the_core_schema() {
    let sql = include_str!("../../migrations/0001_init.sql");
    assert!(sql.contains("CREATE TABLE tenants"));
    assert!(sql.contains("00000000-0000-0000-0000-000000000001"));
    assert!(sql.contains("'default'"));
    assert!(sql.contains("'owner'"));
    for table in TENANT_TABLES {
        assert!(
            sql.contains(&format!("CREATE TABLE {table}")),
            "missing {table}"
        );
        assert!(
            sql.contains("tenant_id uuid NOT NULL REFERENCES tenants (id)"),
            "{table} must reference tenants"
        );
    }
    assert_eq!(
        TenantId::default_tenant().0,
        crate::store::DEFAULT_TENANT_ID
    );
}

#[tokio::test]
async fn db_migrations_are_idempotent() {
    with_database(|db| async move {
        db.migrate().await?;
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&db.pool)
            .await
            .map_err(super::db_err)?;
        assert_eq!(
            applied as usize,
            sqlx::migrate!("./migrations").iter().count()
        );
        let names: Vec<String> = sqlx::query_scalar("SELECT name FROM tenants ORDER BY name")
            .fetch_all(&db.pool)
            .await
            .map_err(super::db_err)?;
        assert_eq!(names, vec!["default".to_string()]);
        let missing: Vec<String> = sqlx::query_scalar(
            "SELECT t.table_name
             FROM information_schema.tables t
             WHERE t.table_schema = 'public'
               AND t.table_type = 'BASE TABLE'
               AND t.table_name <> '_sqlx_migrations'
               AND t.table_name <> 'tenants'
               AND NOT EXISTS (
                   SELECT 1
                   FROM information_schema.columns c
                   WHERE c.table_schema = t.table_schema
                     AND c.table_name = t.table_name
                     AND c.column_name = 'tenant_id'
                     AND c.is_nullable = 'NO'
               )
             ORDER BY t.table_name",
        )
        .fetch_all(&db.pool)
        .await
        .map_err(super::db_err)?;
        assert!(missing.is_empty(), "missing tenant_id: {missing:?}");
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn db_repositories_filter_by_tenant() {
    with_database(|db| async move {
        let tenant = TenantId::default_tenant();
        let other = TenantId::from_uuid(Uuid::from_u128(2));
        db.insert_tenant(&other, "other").await?;
        let seeded = db.get_tenant(&tenant).await?.expect("default tenant");
        assert_eq!(seeded.name, "default");

        let group = db
            .insert_host_group(
                &tenant,
                NewHostGroup {
                    name: "linux".to_string(),
                },
            )
            .await?;
        let user = db
            .insert_user(
                &tenant,
                NewUser {
                    email: "ops@example.com".to_string(),
                    password_hash: "hash".to_string(),
                    role: "operator".to_string(),
                    host_group_id: Some(group.id),
                },
            )
            .await?;
        db.insert_api_token(
            &tenant,
            NewApiToken {
                user_id: user.id,
                name: "cli".to_string(),
                token_hash: "hashed-token".to_string(),
                expires_at: None,
            },
        )
        .await?;
        let host = db
            .insert_host(
                &tenant,
                NewHost {
                    host_group_id: Some(group.id),
                    name: "web-1".to_string(),
                },
            )
            .await?;
        let agent = db
            .insert_agent(
                &tenant,
                NewAgent {
                    id: Some(Uuid::from_u128(9)),
                    host_id: Some(host.id),
                    hostname: "web-1".to_string(),
                    os: "linux".to_string(),
                    arch: "x86_64".to_string(),
                    cert_serial: "aa".to_string(),
                    cert_not_after: None,
                },
            )
            .await?;
        let template = db
            .insert_template(
                &tenant,
                NewTemplate {
                    name: "Linux".to_string(),
                    description: "host".to_string(),
                },
            )
            .await?;
        db.insert_item(
            &tenant,
            NewItem {
                template_id: template.id,
                key: "cpu".to_string(),
                kind: "metric".to_string(),
                interval_s: 60,
                params: serde_json::json!({}),
            },
        )
        .await?;
        let trigger = db
            .insert_trigger(
                &tenant,
                NewTrigger {
                    template_id: Some(template.id),
                    host_id: Some(host.id),
                    name: "disk".to_string(),
                    expression: "kestrel_filesystem_used_ratio > 0.9".to_string(),
                    severity: "high".to_string(),
                    for_seconds: 300,
                    recovery_expr: None,
                    labels: serde_json::json!({"team": "ops"}),
                },
            )
            .await?;
        let problem = db
            .insert_problem(
                &tenant,
                NewProblem {
                    trigger_id: trigger.id,
                    host_id: Some(host.id),
                    status: "problem".to_string(),
                    severity: "high".to_string(),
                },
            )
            .await?;
        let media = db
            .insert_media_type(
                &tenant,
                NewMediaType {
                    name: "mail".to_string(),
                    kind: "email".to_string(),
                    config: serde_json::json!({"to": "ops@example.com"}),
                },
            )
            .await?;
        db.insert_action(
            &tenant,
            NewAction {
                name: "email ops".to_string(),
                media_type_id: Some(media.id),
            },
        )
        .await?;
        db.insert_notification_job(
            &tenant,
            NewNotificationJob {
                problem_id: Some(problem.id),
                media_type_id: media.id,
                payload: serde_json::json!({"problem": problem.id}),
            },
        )
        .await?;
        let start = Utc::now();
        db.insert_maintenance(
            &tenant,
            NewMaintenance {
                name: "window".to_string(),
                host_group_id: Some(group.id),
                starts_at: start,
                ends_at: start + Duration::hours(1),
                rrule: None,
            },
        )
        .await?;
        db.insert_audit(
            &tenant,
            NewAuditEntry {
                user_id: Some(user.id),
                action: "host.create".to_string(),
                target: host.id.to_string(),
                detail: serde_json::json!({}),
            },
        )
        .await?;

        let revoked = db.revoke_agent(&tenant, agent.id).await?;
        assert!(revoked.revoked_at.is_some());
        let hosts = db
            .list_hosts(
                &tenant,
                HostFilter {
                    host_group_id: Some(group.id),
                    name: Some("web-1".to_string()),
                },
            )
            .await?;
        assert_eq!(hosts.len(), 1);
        assert!(db.get_host(&other, host.id).await?.is_none());
        assert!(db
            .list_hosts(&other, HostFilter::default())
            .await?
            .is_empty());
        assert!(db.list_host_groups(&other).await?.is_empty());
        assert!(db.list_users(&other).await?.is_empty());
        assert!(db.list_api_tokens(&other).await?.is_empty());
        assert!(db.list_agents(&other).await?.is_empty());
        assert!(db.list_templates(&other).await?.is_empty());
        assert!(db.list_items(&other).await?.is_empty());
        assert!(db.list_triggers(&other).await?.is_empty());
        assert!(db.list_problems(&other).await?.is_empty());
        assert!(db.list_actions(&other).await?.is_empty());
        assert!(db.list_media_types(&other).await?.is_empty());
        assert!(db.list_notification_jobs(&other).await?.is_empty());
        assert!(db.list_maintenances(&other).await?.is_empty());
        assert!(db.list_audit_log(&other).await?.is_empty());
        assert_eq!(
            db.list_hosts(&tenant, HostFilter::default()).await?.len(),
            1
        );
        Ok(())
    })
    .await;
}

async fn with_database<F, Fut>(test: F)
where
    F: FnOnce(Db) -> Fut,
    Fut: std::future::Future<Output = Result<(), crate::ServerError>>,
{
    let Some(url) = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        eprintln!("DATABASE_URL is unset; skipping PostgreSQL test");
        return;
    };
    let opts = PgConnectOptions::from_str(&url).expect("DATABASE_URL parses");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts.clone())
        .await
        .expect("connect to PostgreSQL");
    let version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&admin)
        .await
        .expect("server version");
    assert!(
        version.starts_with("16."),
        "PostgreSQL 16 is required, found {version}"
    );
    let name = format!("kestrel_test_{}", Uuid::new_v4().simple());
    assert!(name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'));
    sqlx::raw_sql(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("create test database");
    let test_opts = opts.database(&name);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(test_opts)
        .await
        .expect("connect to the test database");
    let db = Db::from_pool(pool).await.expect("apply migrations");
    let outcome = test(db).await;
    let drop_result = sqlx::raw_sql(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await;
    outcome.expect("repository test");
    drop_result.expect("drop test database");
}
