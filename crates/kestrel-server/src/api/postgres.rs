//! PostgreSQL API persistence. Identifiers come exclusively from the static
//! resource map; all request values are bound parameters.

use super::{fail, ApiError, ApiState, Principal};
use crate::passwords::{hash_password, random_token, token_hash, verify_password};
use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

fn database_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref database) = error {
        if database.is_unique_violation() {
            return fail(StatusCode::CONFLICT, "resource already exists");
        }
        if database.is_foreign_key_violation() || database.is_check_violation() {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid resource reference or value",
            );
        }
        if database
            .code()
            .is_some_and(|code| code.starts_with("22") || code == "23502")
        {
            return fail(StatusCode::BAD_REQUEST, "invalid resource value");
        }
    }
    // PostgreSQL diagnostics may include passwords or notification credentials.
    fail(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database operation failed",
    )
}

fn resource(kind: &str) -> Result<(&'static str, &'static str, Value), ApiError> {
    Ok(match kind {
        "host" => ("hosts", "name,host_group_id", json!({})),
        "host_group" => ("host_groups", "name", json!({})),
        "trigger" => ("triggers", "name,expression,severity,template_id,host_id,for_seconds,recovery_expr,labels,interval_s,recover_for", json!({"severity":"warning","for_seconds":0,"labels":{},"interval_s":15,"recover_for":0})),
        "problem" => ("problems", "trigger_id,host_id,status,severity", json!({"status":"problem","severity":"warning"})),
        "action" => ("actions", "name,media_type_id", json!({})),
        "action_step" => ("action_steps", "action_id,step,delay_s,media_type_ids,user_group_ids", json!({"delay_s":0,"media_type_ids":[],"user_group_ids":[]})),
        "user" => ("users", "email,password_hash,role,host_group_id", json!({"role":"viewer"})),
        "token" => ("api_tokens", "user_id,name,token_hash,expires_at", json!({"name":"API token"})),
        "media" => ("media_types", "name,kind,config", json!({"config":{}})),
        "dashboard" => ("dashboards", "name,layout", json!({"layout":{}})),
        "template" => ("templates", "name,description", json!({"description":""})),
        "item" => ("items", "template_id,key,kind,interval_s,params", json!({"interval_s":30,"params":{}})),
        "discovery_rule"=>("discovery_rules","template_id,name,entity,filter,item_prototype,trigger_prototype,keep_days",json!({"filter":"","item_prototype":"","trigger_prototype":"","keep_days":7})),
        "maintenance" => ("maintenances", "name,host_group_id,starts_at,ends_at,rrule,host_ids,group_ids,collect_data,suppress_problems", json!({"host_ids":[],"group_ids":[],"collect_data":true,"suppress_problems":true})),
        _ => return Err(fail(StatusCode::BAD_REQUEST, "unknown resource")),
    })
}

fn scope(principal: &Principal, kind: &str) -> (String, Option<Uuid>) {
    let group = crate::authz::scope_for(
        principal.tenant_id,
        &principal.role,
        principal.host_group_id,
    )
    .groups
    .and_then(|groups| groups.first().copied());
    let clause = match (group, kind) {
        (None, _) => "TRUE",
        (Some(_), "host" | "user" | "maintenance") => "r.host_group_id = $2",
        (Some(_), "host_group") => "r.id = $2",
        (Some(_), "problem" | "trigger") => "EXISTS (SELECT 1 FROM hosts h WHERE h.tenant_id = r.tenant_id AND h.id = r.host_id AND h.host_group_id = $2)",
        (Some(_), "dashboard") => "TRUE",
        (Some(_), _) => "FALSE",
    };
    (clause.to_string(), group)
}

fn public(mut value: Value) -> Value {
    if let Some(body) = value.as_object_mut() {
        for key in ["password", "password_hash", "token_hash", "config"] {
            body.remove(key);
        }
    }
    value
}

fn projection(kind: &str) -> &'static str {
    if kind == "host" {
        "to_jsonb(r) || jsonb_build_object('status',CASE WHEN EXISTS (SELECT 1 FROM agents a WHERE a.tenant_id=r.tenant_id AND a.host_id=r.id AND a.revoked_at IS NULL AND a.last_seen_at>now()-interval '180 seconds') THEN 'up' WHEN EXISTS (SELECT 1 FROM agents a WHERE a.tenant_id=r.tenant_id AND a.host_id=r.id AND a.last_seen_at IS NOT NULL) THEN 'down' ELSE 'unknown' END,'last_seen_at',(SELECT max(a.last_seen_at) FROM agents a WHERE a.tenant_id=r.tenant_id AND a.host_id=r.id))"
    } else if kind == "problem" {
        "to_jsonb(r) || jsonb_build_object('name',concat_ws(' on ',(SELECT t.name FROM triggers t WHERE t.tenant_id=r.tenant_id AND t.id=r.trigger_id),(SELECT h.name FROM hosts h WHERE h.tenant_id=r.tenant_id AND h.id=r.host_id)))"
    } else {
        "to_jsonb(r)"
    }
}

impl ApiState {
    pub(super) async fn pg_update_tenant(
        &self,
        principal: &Principal,
        id: Uuid,
        body: Value,
    ) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let host = body
            .get("host_quota")
            .map(|value| {
                value
                    .as_i64()
                    .filter(|value| *value > 0 && *value <= 1_000_000)
                    .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "invalid host_quota"))
            })
            .transpose()?;
        let rate = body
            .get("samples_per_second")
            .map(|value| {
                value
                    .as_i64()
                    .filter(|value| *value > 0 && *value <= 1_000_000_000)
                    .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "invalid samples_per_second"))
            })
            .transpose()?;
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let row:Option<Value>=sqlx::query_scalar("UPDATE tenants SET host_quota=COALESCE($3,host_quota),samples_per_second=COALESCE($4,samples_per_second),updated_at=now() WHERE id=$1 AND (parent_id=$2 OR (id=$2 AND id='00000000-0000-0000-0000-000000000001'::uuid)) RETURNING to_jsonb(tenants.*)").bind(id).bind(principal.tenant_id).bind(host.map(|v|v as i32)).bind(rate.map(|v|v as i32)).fetch_optional(&mut *tx).await.map_err(database_error)?;
        let row = row.ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))?;
        audit(&mut tx, principal, "tenant.update", &id.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(row)
    }
    pub(super) async fn pg_link_parent(
        &self,
        principal: &Principal,
        template: Uuid,
        parent: Uuid,
    ) -> Result<Value, ApiError> {
        self.pg_get(principal, "template", template, false).await?;
        self.pg_get(principal, "template", parent, false).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,42))")
            .bind(principal.tenant_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        let cycle:bool=sqlx::query_scalar("WITH RECURSIVE ancestors(id) AS (SELECT $2::uuid UNION SELECT p.parent_id FROM template_parents p JOIN ancestors a ON p.template_id=a.id WHERE p.tenant_id=$1) SELECT EXISTS(SELECT 1 FROM ancestors WHERE id=$3)").bind(principal.tenant_id).bind(parent).bind(template).fetch_one(&mut *tx).await.map_err(database_error)?;
        if cycle {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "template inheritance cannot contain cycles",
            ));
        }
        sqlx::query("INSERT INTO template_parents (tenant_id,template_id,parent_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING").bind(principal.tenant_id).bind(template).bind(parent).execute(&mut *tx).await.map_err(database_error)?;
        audit(&mut tx, principal, "template.parent", &template.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(json!({"template_id":template,"parent_id":parent}))
    }
    pub(super) async fn pg_record_control(
        &self,
        principal: &Principal,
        action: &str,
        target: &str,
    ) -> Result<(), ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        audit(&mut tx, principal, action, target).await?;
        tx.commit().await.map_err(database_error)
    }
    async fn validate_values(
        &self,
        principal: &Principal,
        kind: &str,
        values: &Value,
    ) -> Result<(), ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        if kind == "discovery_rule" {
            if !matches!(
                values["entity"].as_str(),
                Some("filesystem" | "interface" | "service" | "port")
            ) {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    "unsupported discovery entity",
                ));
            }
            let filter = values["filter"]
                .as_str()
                .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "filter must be text"))?;
            if filter.len() > 200 || regex::Regex::new(filter).is_err() {
                return Err(fail(StatusCode::BAD_REQUEST, "invalid discovery filter"));
            }
            for field in ["item_prototype", "trigger_prototype"] {
                let prototype = values[field]
                    .as_str()
                    .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "prototype must be JSON text"))?;
                if !prototype.is_empty()
                    && serde_json::from_str::<Value>(prototype)
                        .ok()
                        .filter(Value::is_object)
                        .is_none()
                {
                    return Err(fail(
                        StatusCode::BAD_REQUEST,
                        "prototype must contain a JSON object",
                    ));
                }
            }
        }
        let references: &[(&str, &str)] = match kind {
            "maintenance" => &[("host_ids", "hosts"), ("group_ids", "host_groups")],
            "action_step" => &[("media_type_ids", "media_types")],
            _ => &[],
        };
        for (field, table) in references {
            let array = values[*field].as_array().ok_or_else(|| {
                fail(StatusCode::BAD_REQUEST, format!("{field} must be an array"))
            })?;
            let mut ids = array
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(|value| Uuid::parse_str(value).ok())
                        .ok_or_else(|| {
                            fail(
                                StatusCode::BAD_REQUEST,
                                format!("{field} must contain UUIDs"),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ids.sort();
            ids.dedup();
            let sql = format!("SELECT count(*) FROM {table} WHERE tenant_id=$1 AND id=ANY($2)");
            let count: i64 = sqlx::query_scalar(&sql)
                .bind(principal.tenant_id)
                .bind(&ids)
                .fetch_one(&db.pool)
                .await
                .map_err(database_error)?;
            if count != ids.len() as i64 {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    format!("invalid {field} reference"),
                ));
            }
        }
        if kind == "maintenance" {
            let start = values["starts_at"]
                .as_str()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "invalid maintenance start"))?;
            let end = values["ends_at"]
                .as_str()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "invalid maintenance end"))?;
            if end <= start {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    "maintenance end must follow start",
                ));
            }
            if let Some(rule) = values["rrule"].as_str().filter(|value| !value.is_empty()) {
                let rule = if rule.contains("DTSTART") {
                    rule.to_string()
                } else {
                    format!(
                        "DTSTART:{}\nRRULE:{}",
                        start.with_timezone(&chrono::Utc).format("%Y%m%dT%H%M%SZ"),
                        rule.trim_start_matches("RRULE:")
                    )
                };
                rule.parse::<rrule::RRuleSet>()
                    .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid maintenance recurrence"))?;
            }
        }
        Ok(())
    }
    pub(super) async fn pg_snmp(
        &self,
        principal: &Principal,
        id: Uuid,
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        self.pg_get(principal, "host", id, false).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        if let Some(body) = body {
            if !body.is_object()
                || body["addr"]
                    .as_str()
                    .filter(|value| value.parse::<std::net::SocketAddr>().is_ok())
                    .is_none()
                || !matches!(body["version"].as_str(), Some("v2c" | "v3"))
            {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    "valid addr and version are required",
                ));
            }
            if body["version"] == "v2c"
                && body["community"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .is_none()
            {
                return Err(fail(StatusCode::BAD_REQUEST, "community is required"));
            }
            if body["version"] == "v3"
                && ["user", "auth", "privacy"].iter().any(|key| {
                    body[*key]
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .is_none()
                })
            {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    "user, auth and privacy are required",
                ));
            }
            let secrets = self.secrets.as_ref().ok_or_else(|| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "secret store unavailable",
                )
            })?;
            let encrypted = json!({"encrypted":secrets.encrypt(&body.to_string()).map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"secret encryption failed"))?});
            let mut tx = db.pool.begin().await.map_err(database_error)?;
            sqlx::query("INSERT INTO host_snmp (tenant_id,host_id,config) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,host_id) DO UPDATE SET config=EXCLUDED.config").bind(principal.tenant_id).bind(id).bind(encrypted).execute(&mut *tx).await.map_err(database_error)?;
            audit(&mut tx, principal, "host.snmp.update", &id.to_string()).await?;
            tx.commit().await.map_err(database_error)?;
            return Ok(json!({"host_id":id,"configured":true}));
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM host_snmp WHERE tenant_id=$1 AND host_id=$2)",
        )
        .bind(principal.tenant_id)
        .bind(id)
        .fetch_one(&db.pool)
        .await
        .map_err(database_error)?;
        Ok(json!({"host_id":id,"configured":exists}))
    }
    pub(super) async fn pg_principal(
        &self,
        session: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<Option<Principal>, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let row: Option<(Uuid, Uuid, Uuid, String, String, Option<Uuid>)> = if let Some(secret) =
            session
        {
            sqlx::query_as("SELECT u.id,u.tenant_id,s.active_tenant_id,u.email,CASE WHEN s.active_tenant_id=u.tenant_id THEN u.role ELSE (SELECT g.role FROM msp_grants g WHERE g.user_id=u.id AND g.tenant_id=s.active_tenant_id) END,u.host_group_id FROM sessions s JOIN users u ON u.id=s.user_id AND u.tenant_id=s.tenant_id WHERE s.token_hash=$1 AND s.expires_at > now() AND (s.active_tenant_id=s.tenant_id OR EXISTS (SELECT 1 FROM msp_grants g WHERE g.user_id=u.id AND g.tenant_id=s.active_tenant_id))")
                .bind(token_hash(secret)).fetch_optional(&db.pool).await.map_err(database_error)?
        } else if let Some(secret) = bearer {
            sqlx::query_as("SELECT u.id,u.tenant_id,t.tenant_id,u.email,u.role,u.host_group_id FROM api_tokens t JOIN users u ON u.id=t.user_id AND u.tenant_id=t.tenant_id WHERE t.token_hash=$1 AND (t.expires_at IS NULL OR t.expires_at > now())")
                .bind(token_hash(secret)).fetch_optional(&db.pool).await.map_err(database_error)?
        } else {
            None
        };
        Ok(row.map(
            |(user_id, home, tenant_id, email, role, host_group_id)| Principal {
                user_id,
                tenant_id,
                email,
                role,
                host_group_id: if home == tenant_id {
                    host_group_id
                } else {
                    None
                },
            },
        ))
    }

    pub(super) async fn pg_login(&self, email: &str, password: &str) -> Result<String, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        // Ambiguous email addresses fail closed; an explicit tenant login can be
        // added without allowing one tenant's password to select another user.
        let users: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT id,tenant_id,password_hash FROM users WHERE email=$1 ORDER BY id LIMIT 2",
        )
        .bind(email)
        .fetch_all(&db.pool)
        .await
        .map_err(database_error)?;
        let user = users.first().filter(|_| users.len() == 1);
        let valid = verify_password(password, user.map(|row| row.2.as_str()).unwrap_or(""));
        let (id, tenant, _) = user
            .filter(|_| valid)
            .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "invalid email or password"))?;
        let secret = random_token("sess_")
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "session creation failed"))?;
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        sqlx::query("DELETE FROM sessions WHERE expires_at <= now() AND user_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("INSERT INTO sessions (tenant_id,active_tenant_id,user_id,token_hash,expires_at) VALUES ($1,$1,$2,$3,now()+interval '24 hours')")
            .bind(tenant).bind(id).bind(token_hash(&secret)).execute(&mut *tx).await.map_err(database_error)?;
        let principal = Principal {
            user_id: *id,
            tenant_id: *tenant,
            email: email.to_string(),
            role: String::new(),
            host_group_id: None,
        };
        audit(&mut tx, &principal, "session.login", &id.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(secret)
    }

    pub(super) async fn pg_logout(
        &self,
        principal: &Principal,
        secret: &str,
    ) -> Result<(), ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        sqlx::query("DELETE FROM sessions WHERE token_hash=$1 AND user_id=$2")
            .bind(token_hash(secret))
            .bind(principal.user_id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        audit(
            &mut tx,
            principal,
            "session.logout",
            &principal.user_id.to_string(),
        )
        .await?;
        tx.commit().await.map_err(database_error)
    }

    pub(super) async fn pg_list(
        &self,
        principal: &Principal,
        kind: &str,
        limit: usize,
        cursor: Option<&str>,
        status: Option<&str>,
    ) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        if kind == "tenant" {
            return self.pg_overview(principal).await;
        }
        let (table, _, _) = resource(kind)?;
        let (scope, group) = scope(principal, kind);
        let cursor = cursor
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid cursor"))?;
        let limit = limit.clamp(1, 200);
        let projection = projection(kind);
        // Only problems expose a status filter; other tables may lack the column.
        let status = status.filter(|_| kind == "problem");
        let filter = if status.is_some() {
            " AND r.status = $5"
        } else {
            ""
        };
        let sql=format!("SELECT {projection} FROM {table} r WHERE r.tenant_id=$1 AND ({scope}) AND ($2::uuid IS NULL OR TRUE) AND ($3::uuid IS NULL OR r.id > $3){filter} ORDER BY r.id LIMIT $4");
        let mut query = sqlx::query_scalar(&sql)
            .bind(principal.tenant_id)
            .bind(group)
            .bind(cursor)
            .bind((limit + 1) as i64);
        if let Some(status) = status {
            query = query.bind(status);
        }
        let mut rows: Vec<Value> = query.fetch_all(&db.pool).await.map_err(database_error)?;
        let next = if rows.len() > limit {
            rows[limit - 1]["id"].clone()
        } else {
            Value::Null
        };
        rows.truncate(limit);
        Ok(json!({"items":rows.into_iter().map(public).collect::<Vec<_>>(),"next":next}))
    }

    pub(super) async fn pg_get(
        &self,
        principal: &Principal,
        kind: &str,
        id: Uuid,
        include_config: bool,
    ) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let (table, _, _) = resource(kind)?;
        let (scope, group) = scope(principal, kind);
        let projection = projection(kind);
        let sql=format!("SELECT {projection} FROM {table} r WHERE r.tenant_id=$1 AND ({scope}) AND ($2::uuid IS NULL OR TRUE) AND r.id=$3");
        let mut row: Value = sqlx::query_scalar(&sql)
            .bind(principal.tenant_id)
            .bind(group)
            .bind(id)
            .fetch_optional(&db.pool)
            .await
            .map_err(database_error)?
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))?;
        if kind == "media" && include_config {
            let encrypted = row["config"]["encrypted"].as_str().ok_or_else(|| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "media configuration unavailable",
                )
            })?;
            let secrets = self.secrets.as_ref().ok_or_else(|| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "secret store unavailable",
                )
            })?;
            row["config"] = serde_json::from_str(&secrets.decrypt(encrypted).map_err(|_| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "media configuration unavailable",
                )
            })?)
            .map_err(|_| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "media configuration unavailable",
                )
            })?;
            return Ok(row);
        }
        Ok(public(row))
    }

    pub(super) async fn pg_insert(
        &self,
        principal: &Principal,
        kind: &str,
        body: Value,
    ) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let (table, columns, mut values) = resource(kind)?;
        let input = body
            .as_object()
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "JSON object required"))?;
        values.as_object_mut().unwrap().extend(input.clone());
        let id = Uuid::new_v4();
        values["id"] = json!(id);
        values["tenant_id"] = json!(principal.tenant_id);
        self.validate_values(principal, kind, &values).await?;
        let mut revealed = None;
        if kind == "user" {
            if values["role"] == "owner" && principal.role != "owner" {
                return Err(fail(
                    StatusCode::FORBIDDEN,
                    "only an owner can grant the owner role",
                ));
            }
            let password = body["password"]
                .as_str()
                .filter(|value| value.len() >= 8)
                .ok_or_else(|| {
                    fail(
                        StatusCode::BAD_REQUEST,
                        "password must be at least 8 characters",
                    )
                })?
                .to_string();
            values["password_hash"] = json!(tokio::task::spawn_blocking(move || hash_password(
                &password
            ))
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?);
        }
        if kind == "token" {
            let user_id = body
                .get("user_id")
                .map(|value| {
                    value
                        .as_str()
                        .and_then(|value| Uuid::parse_str(value).ok())
                        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "invalid user_id"))
                })
                .transpose()?
                .unwrap_or(principal.user_id);
            let role: Option<String> =
                sqlx::query_scalar("SELECT role FROM users WHERE tenant_id=$1 AND id=$2")
                    .bind(principal.tenant_id)
                    .bind(user_id)
                    .fetch_optional(&db.pool)
                    .await
                    .map_err(database_error)?;
            let role = role.ok_or_else(|| {
                fail(
                    StatusCode::BAD_REQUEST,
                    "a user in the active tenant is required",
                )
            })?;
            if role == "owner" && principal.role != "owner" {
                return Err(fail(
                    StatusCode::FORBIDDEN,
                    "only an owner can create owner tokens",
                ));
            }
            let secret = random_token("kst_")
                .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "token creation failed"))?;
            values["user_id"] = json!(user_id);
            values["token_hash"] = json!(token_hash(&secret));
            revealed = Some(secret);
        }
        if kind == "media" {
            let mut config = body.get("config").cloned().unwrap_or_else(|| body.clone());
            if let Some(object) = config.as_object_mut() {
                object.remove("name");
                object.remove("kind");
            }
            let secrets = self.secrets.as_ref().ok_or_else(|| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "secret store unavailable",
                )
            })?;
            values["config"] = json!({"encrypted":secrets.encrypt(&config.to_string()).map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"secret encryption failed"))?});
        }
        if kind == "trigger" {
            for field in ["expression", "recovery_expr"] {
                if let Some(expression) = values[field].as_str().filter(|s| !s.is_empty()) {
                    crate::promql::inject_scope(expression, &principal.tenant_id.to_string(), None)
                        .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid PromQL expression"))?;
                }
            }
        }
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        if kind == "host" {
            // Lock the tenant so simultaneous creations cannot exceed its quota.
            let quota: i32 =
                sqlx::query_scalar("SELECT host_quota FROM tenants WHERE id=$1 FOR UPDATE")
                    .bind(principal.tenant_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(database_error)?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts WHERE tenant_id=$1")
                .bind(principal.tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
            if count >= i64::from(quota) {
                return Err(fail(StatusCode::TOO_MANY_REQUESTS, "host quota exceeded"));
            }
        }
        let sql=format!("INSERT INTO {table} (id,tenant_id,{columns}) SELECT id,tenant_id,{columns} FROM jsonb_populate_record(NULL::{table},$1) RETURNING to_jsonb({table}.*)");
        let row: Value = sqlx::query_scalar(&sql)
            .bind(values)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
        audit(
            &mut tx,
            principal,
            &format!("{kind}.create"),
            &id.to_string(),
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        let mut row = public(row);
        if let Some(secret) = revealed {
            row["token"] = json!(secret);
        }
        Ok(row)
    }

    pub(super) async fn pg_update_dashboard(
        &self,
        principal: &Principal,
        id: Uuid,
        body: Value,
    ) -> Result<Value, ApiError> {
        self.pg_get(principal, "dashboard", id, false).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let name = body["name"]
            .as_str()
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "name is required"))?;
        let layout = body
            .get("layout")
            .cloned()
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "layout is required"))?;
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let row:Value=sqlx::query_scalar("UPDATE dashboards SET name=$3,layout=$4,updated_at=now() WHERE tenant_id=$1 AND id=$2 RETURNING to_jsonb(dashboards.*)").bind(principal.tenant_id).bind(id).bind(name).bind(layout).fetch_one(&mut *tx).await.map_err(database_error)?;
        audit(&mut tx, principal, "dashboard.update", &id.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(row)
    }

    pub(super) async fn pg_ack(
        &self,
        principal: &Principal,
        id: Uuid,
        comment: &str,
    ) -> Result<Value, ApiError> {
        self.pg_get(principal, "problem", id, false).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let row:Value=sqlx::query_scalar("UPDATE problems SET acknowledged_at=now(),acknowledged_by=$3,acknowledgement_comment=$4 WHERE tenant_id=$1 AND id=$2 RETURNING to_jsonb(problems.*)").bind(principal.tenant_id).bind(id).bind(principal.user_id).bind(comment).fetch_one(&mut *tx).await.map_err(database_error)?;
        sqlx::query("INSERT INTO problem_events (tenant_id,problem_id,kind,detail) VALUES ($1,$2,'acknowledged',$3)").bind(principal.tenant_id).bind(id).bind(json!({"user_id":principal.user_id,"comment":comment})).execute(&mut *tx).await.map_err(database_error)?;
        audit(&mut tx, principal, "problem.ack", &id.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(row)
    }

    pub(super) async fn pg_audits(&self, principal: &Principal) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        // A group-scoped reader cannot inspect writes outside that group.
        if crate::authz::scope_for(
            principal.tenant_id,
            &principal.role,
            principal.host_group_id,
        )
        .groups
        .is_some()
        {
            return Ok(json!({"items":[]}));
        }
        let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_log a WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT 200").bind(principal.tenant_id).fetch_all(&db.pool).await.map_err(database_error)?;
        Ok(json!({"items":rows}))
    }

    pub(super) async fn pg_host_names(
        &self,
        principal: &Principal,
    ) -> Result<Option<Vec<String>>, ApiError> {
        let groups = crate::authz::scope_for(
            principal.tenant_id,
            &principal.role,
            principal.host_group_id,
        )
        .groups;
        let Some(groups) = groups else {
            return Ok(None);
        };
        let db = self.db.as_ref().expect("PostgreSQL state");
        let names = sqlx::query_scalar(
            "SELECT name FROM hosts WHERE tenant_id=$1 AND host_group_id=ANY($2)",
        )
        .bind(principal.tenant_id)
        .bind(groups)
        .fetch_all(&db.pool)
        .await
        .map_err(database_error)?;
        Ok(Some(names))
    }

    pub(super) async fn pg_switch(
        &self,
        principal: &Principal,
        secret: &str,
        target: Uuid,
    ) -> Result<(), ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let updated=sqlx::query("UPDATE sessions s SET active_tenant_id=$3 WHERE s.token_hash=$1 AND s.user_id=$2 AND s.expires_at>now() AND (s.tenant_id=$3 OR EXISTS (SELECT 1 FROM msp_grants g WHERE g.user_id=s.user_id AND g.tenant_id=$3))").bind(token_hash(secret)).bind(principal.user_id).bind(target).execute(&mut *tx).await.map_err(database_error)?;
        if updated.rows_affected() != 1 {
            return Err(fail(StatusCode::FORBIDDEN, "not allowed"));
        }
        audit(
            &mut tx,
            principal,
            "session.switch_tenant",
            &target.to_string(),
        )
        .await?;
        tx.commit().await.map_err(database_error)
    }

    pub(super) async fn pg_overview(&self, principal: &Principal) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',t.id,'tenant_id',t.id,'name',t.name,'parent_id',t.parent_id,'active',t.id=$2,'problem_count',(SELECT count(*) FROM problems p WHERE p.tenant_id=t.id AND p.status='problem' AND (t.id<>u.tenant_id OR u.role IN ('owner','admin') OR u.host_group_id IS NULL OR EXISTS (SELECT 1 FROM hosts h WHERE h.tenant_id=p.tenant_id AND h.id=p.host_id AND h.host_group_id=u.host_group_id)))) FROM tenants t JOIN users u ON u.id=$1 WHERE EXISTS (SELECT 1 FROM msp_grants g WHERE g.tenant_id=t.id AND g.user_id=u.id) OR t.id=u.tenant_id ORDER BY t.name").bind(principal.user_id).bind(principal.tenant_id).fetch_all(&db.pool).await.map_err(database_error)?;
        Ok(json!({"items":rows}))
    }

    pub(super) async fn pg_grant(
        &self,
        principal: &Principal,
        user: Uuid,
        target: Uuid,
        role: &str,
    ) -> Result<Value, ApiError> {
        if !matches!(role, "admin" | "operator" | "viewer") {
            return Err(fail(StatusCode::BAD_REQUEST, "invalid grant role"));
        }
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        // Owners may grant access only to a direct child and a user in their
        // own tenant. An arbitrary tenant UUID never conveys authority.
        let allowed:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants t JOIN users u ON u.tenant_id=t.parent_id WHERE t.id=$1 AND t.parent_id=$2 AND u.id=$3)").bind(target).bind(principal.tenant_id).bind(user).fetch_one(&mut *tx).await.map_err(database_error)?;
        if !allowed {
            return Err(fail(StatusCode::FORBIDDEN, "not allowed"));
        }
        sqlx::query(
            "INSERT INTO msp_grants (tenant_id,user_id,role) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role",
        )
        .bind(target)
        .bind(user)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        audit(&mut tx, principal, "grant.create", &target.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(json!({"user_id":user,"tenant_id":target}))
    }

    pub(super) async fn pg_link_template(
        &self,
        principal: &Principal,
        host: Uuid,
        template: Uuid,
    ) -> Result<Value, ApiError> {
        self.pg_get(principal, "host", host, false).await?;
        self.pg_get(principal, "template", template, false).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        sqlx::query("INSERT INTO template_links (tenant_id,host_id,template_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING").bind(principal.tenant_id).bind(host).bind(template).execute(&mut *tx).await.map_err(database_error)?;
        audit(&mut tx, principal, "template.link", &host.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(json!({"host_id":host,"template_id":template}))
    }

    pub(super) async fn pg_export_template(
        &self,
        principal: &Principal,
        id: Uuid,
    ) -> Result<crate::config_compile::TemplateDoc, ApiError> {
        let template = self.pg_get(principal, "template", id, false).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let items:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('key',key,'kind',kind,'interval_s',interval_s,'params',params) FROM items WHERE tenant_id=$1 AND template_id=$2 ORDER BY key").bind(principal.tenant_id).bind(id).fetch_all(&db.pool).await.map_err(database_error)?;
        let triggers:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('name',name,'expression',expression,'severity',severity,'for_seconds',for_seconds) FROM triggers WHERE tenant_id=$1 AND template_id=$2 ORDER BY name").bind(principal.tenant_id).bind(id).fetch_all(&db.pool).await.map_err(database_error)?;
        serde_json::from_value(json!({"name":template["name"],"description":template["description"],"items":items,"triggers":triggers})).map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"invalid template configuration"))
    }

    pub(super) async fn pg_import_template(
        &self,
        principal: &Principal,
        doc: crate::config_compile::TemplateDoc,
    ) -> Result<Value, ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let id = Uuid::new_v4();
        let row:Value=sqlx::query_scalar("INSERT INTO templates (id,tenant_id,name,description) VALUES ($1,$2,$3,$4) RETURNING to_jsonb(templates.*)").bind(id).bind(principal.tenant_id).bind(doc.name).bind(doc.description).fetch_one(&mut *tx).await.map_err(database_error)?;
        for item in doc.items {
            sqlx::query("INSERT INTO items (tenant_id,template_id,key,kind,interval_s,params) VALUES ($1,$2,$3,$4,$5,$6)").bind(principal.tenant_id).bind(id).bind(item.key).bind(item.kind).bind(i32::try_from(item.interval_s).map_err(|_|fail(StatusCode::BAD_REQUEST,"invalid item interval"))?).bind(item.params).execute(&mut *tx).await.map_err(database_error)?;
        }
        for trigger in doc.triggers {
            crate::promql::inject_scope(
                &trigger.expression,
                &principal.tenant_id.to_string(),
                None,
            )
            .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid PromQL expression"))?;
            sqlx::query("INSERT INTO triggers (tenant_id,template_id,name,expression,severity,for_seconds) VALUES ($1,$2,$3,$4,$5,$6)").bind(principal.tenant_id).bind(id).bind(trigger.name).bind(trigger.expression).bind(trigger.severity).bind(i32::try_from(trigger.for_seconds).map_err(|_|fail(StatusCode::BAD_REQUEST,"invalid trigger delay"))?).execute(&mut *tx).await.map_err(database_error)?;
        }
        audit(&mut tx, principal, "template.import", &id.to_string()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(row)
    }

    pub(super) async fn pg_record_media_test(
        &self,
        principal: &Principal,
        id: Uuid,
    ) -> Result<(), ApiError> {
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        audit(&mut tx, principal, "media.test", &id.to_string()).await?;
        tx.commit().await.map_err(database_error)
    }

    pub(super) async fn pg_update(
        &self,
        principal: &Principal,
        kind: &str,
        id: Uuid,
        body: Value,
    ) -> Result<Value, ApiError> {
        let mut preview = self.pg_get(principal, kind, id, false).await?;
        let (table, columns, _) = resource(kind)?;
        let input = body
            .as_object()
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "JSON object required"))?;
        preview.as_object_mut().unwrap().extend(input.clone());
        self.validate_values(principal, kind, &preview).await?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let sql =
            format!("SELECT to_jsonb(r) FROM {table} r WHERE tenant_id=$1 AND id=$2 FOR UPDATE");
        let mut values: Value = sqlx::query_scalar(&sql)
            .bind(principal.tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))?;
        if kind == "user"
            && principal.role != "owner"
            && (values["role"] == "owner" || input.get("role").is_some_and(|role| role == "owner"))
        {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "only an owner can manage owners",
            ));
        }
        for column in columns.split(',').filter(|column| {
            !matches!(
                *column,
                "password_hash" | "token_hash" | "user_id" | "config"
            )
        }) {
            if let Some(value) = input.get(column) {
                values[column] = value.clone();
            }
        }
        if kind == "user" {
            if let Some(password) = input.get("password") {
                let password = password
                    .as_str()
                    .filter(|value| value.len() >= 8)
                    .ok_or_else(|| {
                        fail(
                            StatusCode::BAD_REQUEST,
                            "password must be at least 8 characters",
                        )
                    })?
                    .to_string();
                values["password_hash"] = json!(tokio::task::spawn_blocking(
                    move || hash_password(&password)
                )
                .await
                .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?
                .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?);
                sqlx::query("DELETE FROM sessions WHERE tenant_id=$1 AND user_id=$2")
                    .bind(principal.tenant_id)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(database_error)?;
            }
        }
        if kind == "media" && input.get("config").is_some() {
            let secrets = self.secrets.as_ref().ok_or_else(|| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "secret store unavailable",
                )
            })?;
            values["config"] = json!({"encrypted":secrets.encrypt(&input["config"].to_string()).map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"secret encryption failed"))?});
        }
        if kind == "trigger" {
            for field in ["expression", "recovery_expr"] {
                if let Some(expression) = values[field].as_str().filter(|value| !value.is_empty()) {
                    crate::promql::inject_scope(expression, &principal.tenant_id.to_string(), None)
                        .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid PromQL expression"))?;
                }
            }
        }
        let assignments = columns
            .split(',')
            .map(|column| format!("{column}=v.{column}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql=format!("UPDATE {table} r SET {assignments},updated_at=now() FROM jsonb_populate_record(NULL::{table},$3) v WHERE r.tenant_id=$1 AND r.id=$2 RETURNING to_jsonb(r)");
        let row: Value = sqlx::query_scalar(&sql)
            .bind(principal.tenant_id)
            .bind(id)
            .bind(values)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
        audit(
            &mut tx,
            principal,
            &format!("{kind}.update"),
            &id.to_string(),
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(public(row))
    }

    pub(super) async fn pg_delete(
        &self,
        principal: &Principal,
        kind: &str,
        id: Uuid,
    ) -> Result<(), ApiError> {
        let previous = self.pg_get(principal, kind, id, false).await?;
        if kind == "user" && previous["role"] == "owner" && principal.role != "owner" {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "only an owner can delete owners",
            ));
        }
        if kind == "user" && principal.user_id == id {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "cannot delete your own account",
            ));
        }
        let (table, _, _) = resource(kind)?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let sql = format!("DELETE FROM {table} WHERE tenant_id=$1 AND id=$2");
        sqlx::query(&sql)
            .bind(principal.tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        audit(
            &mut tx,
            principal,
            &format!("{kind}.delete"),
            &id.to_string(),
        )
        .await?;
        tx.commit().await.map_err(database_error)
    }

    pub(super) async fn pg_create_tenant(
        &self,
        principal: &Principal,
        body: Value,
    ) -> Result<Value, ApiError> {
        let name = body["name"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "name is required"))?;
        let db = self.db.as_ref().expect("PostgreSQL state");
        let mut tx = db.pool.begin().await.map_err(database_error)?;
        let row: Value = sqlx::query_scalar(
            "INSERT INTO tenants (name,parent_id) VALUES ($1,$2) RETURNING to_jsonb(tenants.*)",
        )
        .bind(name)
        .bind(principal.tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        let id = Uuid::parse_str(row["id"].as_str().unwrap())
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "invalid tenant"))?;
        sqlx::query("INSERT INTO msp_grants (tenant_id,user_id,role) VALUES ($1,$2,'admin')")
            .bind(id)
            .bind(principal.user_id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        audit(&mut tx, principal, "tenant.create", &id.to_string()).await?;
        crate::config_compile::seed_builtin_templates(&mut tx, id)
            .await
            .map_err(|_| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tenant template setup failed",
                )
            })?;
        tx.commit().await.map_err(database_error)?;
        Ok(row)
    }
}

pub(super) async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    principal: &Principal,
    action: &str,
    target: &str,
) -> Result<(), ApiError> {
    // MSP actors belong to their home tenant; preserve the target audit scope
    // without creating an invalid user foreign key.
    sqlx::query("INSERT INTO audit_log (tenant_id,user_id,action,target) VALUES ($1,CASE WHEN EXISTS (SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2) THEN $2 ELSE NULL END,$3,$4)").bind(principal.tenant_id).bind(principal.user_id).bind(action).bind(target).execute(&mut **tx).await.map_err(database_error)?;
    let mut event = crate::forward::api_activity(action, &principal.email, action);
    event["unmapped"] = json!({"target":target,"actor_user_id":principal.user_id});
    crate::runtime::enqueue_forward(tx, principal.tenant_id, "audit", &event)
        .await
        .map_err(|_| {
            fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit forwarding enqueue failed",
            )
        })?;
    Ok(())
}
