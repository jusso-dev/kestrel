//! JSON API, session auth and the OpenAPI document.
//!
//! Handlers are mounted from [`ROUTES`], so a route cannot exist without an
//! [`AuthKind`]. Passwords and tokens are not written to logs.

mod memory;
mod postgres;
#[cfg(test)]
mod postgres_tests;
mod throttle;

pub use memory::{session_cookie, MemoryCatalog, Principal};

use crate::authz::{role_allows, AuthKind, Permission};
use crate::notify::Notifier;
use crate::otlp::{samples_from_json, samples_from_protobuf};
use crate::promql::inject_scope;
use crate::store::{LabelledSample, MetricStore};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{sse::Event, IntoResponse, Response, Sse};
use axum::routing::{get, post, MethodRouter};
use axum::{Json, Router};
use http::HeaderValue;
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

const SESSION_COOKIE: &str = "kestrel_session";

#[derive(Clone, Copy)]
enum Location {
    Api,
    Http,
}

pub(crate) struct RouteSpec {
    method: &'static str,
    path: &'static str,
    operation: &'static str,
    auth: AuthKind,
    location: Location,
}

macro_rules! resource_route {
    ($method:literal,$path:literal,$operation:literal,$permission:ident) => {
        RouteSpec {
            method: $method,
            path: $path,
            operation: $operation,
            auth: AuthKind::User(Permission::$permission),
            location: Location::Api,
        }
    };
}

pub(crate) const ROUTES: &[RouteSpec] = &[
    resource_route!("PUT", "/api/v1/tenants/{id}", "update_tenant", TenantAdmin),
    resource_route!(
        "POST",
        "/api/v1/templates/{id}/parents",
        "link_parent",
        TemplateWrite
    ),
    resource_route!(
        "POST",
        "/api/v1/enrolment-tokens",
        "create_enrolment_token",
        HostWrite
    ),
    resource_route!(
        "GET",
        "/api/v1/discovery-rules",
        "list_discovery_rules",
        TemplateRead
    ),
    resource_route!(
        "POST",
        "/api/v1/discovery-rules",
        "create_discovery_rule",
        TemplateWrite
    ),
    resource_route!(
        "GET",
        "/api/v1/discovery-rules/{id}",
        "get_resource",
        TemplateRead
    ),
    resource_route!(
        "PUT",
        "/api/v1/discovery-rules/{id}",
        "update_resource",
        TemplateWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/discovery-rules/{id}",
        "delete_resource",
        TemplateWrite
    ),
    resource_route!("GET", "/api/v1/hosts/{id}/snmp", "get_snmp", HostRead),
    resource_route!("PUT", "/api/v1/hosts/{id}/snmp", "put_snmp", HostWrite),
    resource_route!("POST", "/api/v1/tenants", "create_tenant", TenantAdmin),
    resource_route!("PUT", "/api/v1/hosts/{id}", "update_resource", HostWrite),
    resource_route!("DELETE", "/api/v1/hosts/{id}", "delete_resource", HostWrite),
    resource_route!("GET", "/api/v1/host-groups/{id}", "get_resource", GroupRead),
    resource_route!(
        "PUT",
        "/api/v1/host-groups/{id}",
        "update_resource",
        GroupWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/host-groups/{id}",
        "delete_resource",
        GroupWrite
    ),
    resource_route!("GET", "/api/v1/triggers/{id}", "get_resource", TriggerRead),
    resource_route!(
        "PUT",
        "/api/v1/triggers/{id}",
        "update_resource",
        TriggerWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/triggers/{id}",
        "delete_resource",
        TriggerWrite
    ),
    resource_route!("GET", "/api/v1/actions/{id}", "get_resource", ActionRead),
    resource_route!(
        "PUT",
        "/api/v1/actions/{id}",
        "update_resource",
        ActionWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/actions/{id}",
        "delete_resource",
        ActionWrite
    ),
    resource_route!("GET", "/api/v1/users/{id}", "get_resource", UserRead),
    resource_route!("PUT", "/api/v1/users/{id}", "update_resource", AdminUsers),
    resource_route!(
        "DELETE",
        "/api/v1/users/{id}",
        "delete_resource",
        AdminUsers
    ),
    resource_route!("GET", "/api/v1/api-tokens/{id}", "get_resource", UserRead),
    resource_route!(
        "PUT",
        "/api/v1/api-tokens/{id}",
        "update_resource",
        AdminUsers
    ),
    resource_route!(
        "DELETE",
        "/api/v1/api-tokens/{id}",
        "delete_resource",
        AdminUsers
    ),
    resource_route!("GET", "/api/v1/media-types/{id}", "get_resource", MediaRead),
    resource_route!(
        "PUT",
        "/api/v1/media-types/{id}",
        "update_resource",
        MediaWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/media-types/{id}",
        "delete_resource",
        MediaWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/dashboards/{id}",
        "delete_resource",
        DashboardWrite
    ),
    resource_route!(
        "PUT",
        "/api/v1/templates/{id}",
        "update_resource",
        TemplateWrite
    ),
    resource_route!(
        "GET",
        "/api/v1/templates/{id}",
        "get_resource",
        TemplateRead
    ),
    resource_route!(
        "DELETE",
        "/api/v1/templates/{id}",
        "delete_resource",
        TemplateWrite
    ),
    resource_route!("GET", "/api/v1/items/{id}", "get_resource", TemplateRead),
    resource_route!(
        "PUT",
        "/api/v1/items/{id}",
        "update_resource",
        TemplateWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/items/{id}",
        "delete_resource",
        TemplateWrite
    ),
    resource_route!(
        "GET",
        "/api/v1/maintenances/{id}",
        "get_resource",
        MaintenanceRead
    ),
    resource_route!(
        "PUT",
        "/api/v1/maintenances/{id}",
        "update_resource",
        MaintenanceWrite
    ),
    resource_route!(
        "DELETE",
        "/api/v1/maintenances/{id}",
        "delete_resource",
        MaintenanceWrite
    ),
    RouteSpec {
        method: "PUT",
        path: "/api/v1/dashboards/{id}",
        operation: "update_dashboard",
        auth: AuthKind::User(Permission::DashboardWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/login",
        operation: "login",
        auth: AuthKind::Public,
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/logout",
        operation: "logout",
        auth: AuthKind::User(Permission::SessionUse),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/openapi.json",
        operation: "openapi",
        auth: AuthKind::Public,
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/enrol",
        operation: "enrol",
        auth: AuthKind::Public,
        location: Location::Http,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/ingest",
        operation: "ingest",
        auth: AuthKind::Agent,
        location: Location::Http,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/renew",
        operation: "renew",
        auth: AuthKind::Agent,
        location: Location::Http,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/agent/config",
        operation: "agent_config",
        auth: AuthKind::Agent,
        location: Location::Http,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/hosts",
        operation: "list_hosts",
        auth: AuthKind::User(Permission::HostRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/hosts",
        operation: "create_host",
        auth: AuthKind::User(Permission::HostWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/hosts/{id}",
        operation: "get_host",
        auth: AuthKind::User(Permission::HostRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/host-groups",
        operation: "list_groups",
        auth: AuthKind::User(Permission::GroupRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/host-groups",
        operation: "create_group",
        auth: AuthKind::User(Permission::GroupWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/triggers",
        operation: "list_triggers",
        auth: AuthKind::User(Permission::TriggerRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/triggers",
        operation: "create_trigger",
        auth: AuthKind::User(Permission::TriggerWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/problems",
        operation: "list_problems",
        auth: AuthKind::User(Permission::ProblemRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/problems/{id}",
        operation: "get_problem",
        auth: AuthKind::User(Permission::ProblemRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/problems/{id}/ack",
        operation: "ack_problem",
        auth: AuthKind::User(Permission::ProblemAck),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/actions",
        operation: "list_actions",
        auth: AuthKind::User(Permission::ActionRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/actions",
        operation: "create_action",
        auth: AuthKind::User(Permission::ActionWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/actions/{id}/steps",
        operation: "create_step",
        auth: AuthKind::User(Permission::ActionWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/users",
        operation: "list_users",
        auth: AuthKind::User(Permission::UserRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/users",
        operation: "create_user",
        auth: AuthKind::User(Permission::AdminUsers),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/tokens",
        operation: "list_tokens",
        auth: AuthKind::User(Permission::UserRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/tokens",
        operation: "create_token",
        auth: AuthKind::User(Permission::AdminUsers),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/media-types",
        operation: "list_media",
        auth: AuthKind::User(Permission::MediaRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/media-types",
        operation: "create_media",
        auth: AuthKind::User(Permission::MediaWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/media-types/{id}/test",
        operation: "test_media",
        auth: AuthKind::User(Permission::MediaWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/dashboards",
        operation: "list_dashboards",
        auth: AuthKind::User(Permission::DashboardRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/dashboards",
        operation: "create_dashboard",
        auth: AuthKind::User(Permission::DashboardWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/dashboards/{id}",
        operation: "get_dashboard",
        auth: AuthKind::User(Permission::DashboardRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/templates",
        operation: "list_templates",
        auth: AuthKind::User(Permission::TemplateRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/templates",
        operation: "create_template",
        auth: AuthKind::User(Permission::TemplateWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/templates/{id}/export",
        operation: "export_template",
        auth: AuthKind::User(Permission::TemplateRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/templates/import",
        operation: "import_template",
        auth: AuthKind::User(Permission::TemplateWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/hosts/{id}/templates",
        operation: "link_template",
        auth: AuthKind::User(Permission::TemplateWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/items",
        operation: "list_items",
        auth: AuthKind::User(Permission::TemplateRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/items",
        operation: "create_item",
        auth: AuthKind::User(Permission::TemplateWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/maintenances",
        operation: "list_maintenances",
        auth: AuthKind::User(Permission::MaintenanceRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/maintenances",
        operation: "create_maintenance",
        auth: AuthKind::User(Permission::MaintenanceWrite),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/audit",
        operation: "list_audit",
        auth: AuthKind::User(Permission::AuditRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/metrics/query",
        operation: "query_instant",
        auth: AuthKind::User(Permission::MetricsRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/metrics/query_range",
        operation: "query_range",
        auth: AuthKind::User(Permission::MetricsRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/events/stream",
        operation: "event_stream",
        auth: AuthKind::User(Permission::ProblemRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/tenants",
        operation: "list_tenants",
        auth: AuthKind::User(Permission::TenantRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/session/tenant",
        operation: "switch_tenant",
        auth: AuthKind::User(Permission::TenantRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/msp/overview",
        operation: "msp_overview",
        auth: AuthKind::User(Permission::MspRead),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/msp/grants",
        operation: "create_grant",
        auth: AuthKind::User(Permission::TenantAdmin),
        location: Location::Api,
    },
    RouteSpec {
        method: "DELETE",
        path: "/api/v1/msp/grants",
        operation: "delete_grant",
        auth: AuthKind::User(Permission::TenantAdmin),
        location: Location::Api,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/metrics",
        operation: "otlp_metrics",
        auth: AuthKind::User(Permission::OtlpWrite),
        location: Location::Api,
    },
];

#[derive(Clone, serde::Serialize)]
pub(crate) struct ProblemNote {
    pub(crate) tenant_id: Uuid,
    pub(crate) problem_id: Uuid,
    pub(crate) kind: String,
}

#[derive(Clone)]
pub struct ApiState {
    pub catalog: Arc<MemoryCatalog>,
    pub store: Arc<dyn MetricStore>,
    pub(crate) events: broadcast::Sender<ProblemNote>,
    pub secure_cookie: bool,
    pub otlp_drop: Vec<String>,
    pub(crate) db: Option<crate::db::Db>,
    pub(crate) secrets: Option<Arc<crate::secrets::SecretBox>>,
    pub(crate) quotas: Arc<crate::quota::Quotas>,
    pub(crate) directory: Option<Arc<crate::store::Directory>>,
    pub(crate) smtp: Option<crate::config::SmtpConfig>,
    /// Outbound policy for tenant-supplied URLs (checks, scrapes, webhooks).
    pub egress: Arc<kestrel_checks::EgressGuard>,
    pub(crate) login_throttle: Arc<throttle::LoginThrottle>,
}

impl ApiState {
    pub fn with_database(
        mut self,
        db: crate::db::Db,
        secrets: Arc<crate::secrets::SecretBox>,
    ) -> Self {
        self.db = Some(db);
        self.secrets = Some(secrets);
        self
    }
    pub fn new(catalog: Arc<MemoryCatalog>, store: Arc<dyn MetricStore>) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            catalog,
            store,
            events,
            secure_cookie: false,
            otlp_drop: vec!["user_id".to_string()],
            db: None,
            secrets: None,
            quotas: Arc::new(crate::quota::Quotas::per_second(50_000)),
            directory: None,
            smtp: None,
            egress: Arc::new(kestrel_checks::EgressGuard::new(false)),
            login_throttle: Arc::default(),
        }
    }
}

pub fn router(state: ApiState) -> Router {
    let mut groups: Vec<(&str, MethodRouter<ApiState>)> = Vec::new();
    for spec in ROUTES {
        if !matches!(spec.location, Location::Api) {
            continue;
        }
        let route = mount(spec);
        if let Some(existing) = groups.iter_mut().find(|(path, _)| *path == spec.path) {
            let taken = std::mem::replace(&mut existing.1, MethodRouter::new());
            existing.1 = taken.merge(route);
        } else {
            groups.push((spec.path, route));
        }
    }
    let mut router = Router::new();
    for (path, methods) in groups {
        router = router.route(&axum_path(path), methods);
    }
    let doc = serde_json::from_value(openapi_value()).expect("valid generated OpenAPI");
    router
        .merge(
            utoipa_swagger_ui::SwaggerUi::new("/api/v1/docs").url("/api/v1/docs/openapi.json", doc),
        )
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            8 * 1024 * 1024,
        ))
        .with_state(state)
}

/// OpenAPI paths use `{id}`. This axum version captures with `:id`.
fn axum_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            out.push(':');
            for next in chars.by_ref() {
                if next == '}' {
                    break;
                }
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn mount(spec: &RouteSpec) -> MethodRouter<ApiState> {
    match spec.operation {
        "login" => post(login),
        "logout" => post(logout),
        "openapi" => get(openapi),
        "update_tenant" => axum::routing::put(update_tenant),
        "link_parent" => post(link_parent),
        "create_enrolment_token" => post(create_enrolment_token),
        "list_discovery_rules" => get(list_discovery_rules),
        "create_discovery_rule" => post(create_discovery_rule),
        "get_snmp" => get(get_snmp),
        "put_snmp" => axum::routing::put(put_snmp),
        "create_tenant" => post(create_tenant),
        "get_resource" => get(get_resource),
        "update_resource" => axum::routing::put(update_resource),
        "delete_resource" => axum::routing::delete(delete_resource),
        "list_hosts" => get(list_hosts),
        "create_host" => post(create_host),
        "get_host" => get(get_host),
        "list_groups" => get(list_groups),
        "create_group" => post(create_group),
        "list_triggers" => get(list_triggers),
        "create_trigger" => post(create_trigger),
        "list_problems" => get(list_problems),
        "get_problem" => get(get_problem),
        "ack_problem" => post(ack_problem),
        "list_actions" => get(list_actions),
        "create_action" => post(create_action),
        "create_step" => post(create_step),
        "list_users" => get(list_users),
        "create_user" => post(create_user),
        "list_tokens" => get(list_tokens),
        "create_token" => post(create_token),
        "list_media" => get(list_media),
        "create_media" => post(create_media),
        "test_media" => post(test_media),
        "list_dashboards" => get(list_dashboards),
        "create_dashboard" => post(create_dashboard),
        "get_dashboard" => get(get_dashboard),
        "update_dashboard" => axum::routing::put(update_dashboard),
        "list_templates" => get(list_templates),
        "create_template" => post(create_template),
        "export_template" => get(export_template),
        "import_template" => post(import_template),
        "link_template" => post(link_template),
        "list_items" => get(list_items),
        "create_item" => post(create_item),
        "list_maintenances" => get(list_maintenances),
        "create_maintenance" => post(create_maintenance),
        "list_audit" => get(list_audit),
        "query_instant" => get(query_instant),
        "query_range" => get(query_range),
        "event_stream" => get(event_stream),
        "list_tenants" => get(list_tenants),
        "switch_tenant" => post(switch_tenant),
        "msp_overview" => get(msp_overview),
        "create_grant" => post(create_grant),
        "delete_grant" => axum::routing::delete(delete_grant),
        "otlp_metrics" => post(otlp_metrics),
        other => panic!("route {other} has no handler"),
    }
}

pub fn openapi_value() -> Value {
    let mut paths = serde_json::Map::new();
    for spec in ROUTES {
        let entry = paths.entry(spec.path).or_insert_with(|| json!({}));
        let method = spec.method.to_ascii_lowercase();
        if let Some(object) = entry.as_object_mut() {
            let mut operation = json!({
                "operationId": if matches!(spec.operation,"get_resource"|"update_resource"|"delete_resource") {format!("{}_{}",spec.operation,spec.path.split('/').nth(3).unwrap_or("resource").replace('-',"_"))} else {spec.operation.to_string()},
                "responses": { "200": { "description": "OK", "content":{"application/json":{"schema":{"type":"object","additionalProperties":true}}}} },
                "security": auth_security(spec.auth),
            });
            let mut parameters = Vec::new();
            if spec.path.contains("{id}") {
                parameters.push(json!({"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
            }
            if matches!(spec.operation, "query_instant" | "query_range") {
                parameters.push(
                    json!({"name":"query","in":"query","required":true,"schema":{"type":"string"}}),
                );
                for name in ["start", "end", "step", "time"] {
                    parameters.push(json!({"name":name,"in":"query","required":spec.operation=="query_range" && matches!(name,"start"|"end"),"schema":{"type":"integer","format":"int64"}}));
                }
            } else if spec.operation.starts_with("list_") {
                parameters.push(json!({"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":200}}));
                parameters.push(json!({"name":"cursor","in":"query","schema":{"type":"string","format":"uuid"}}));
                if spec.operation == "list_problems" {
                    parameters.push(json!({"name":"status","in":"query","schema":{"type":"string","enum":["ok","pending","problem","resolved"]}}));
                }
            }
            for parameter in &mut parameters {
                if parameter.get("required").is_none() {
                    parameter["required"] = json!(false);
                }
            }
            operation["parameters"] = json!(parameters);
            if spec.method == "POST" || spec.method == "PUT" || spec.operation == "delete_grant" {
                let schema = if spec.operation == "login" {
                    json!({"type":"object","required":["email","password"],"properties":{"email":{"type":"string"},"password":{"type":"string","format":"password"}}})
                } else {
                    json!({"type":"object","additionalProperties":true})
                };
                operation["requestBody"] =
                    json!({"required":true,"content":{"application/json":{"schema":schema}}});
            }
            if spec.operation == "login" {
                operation["responses"]["200"]["content"]["application/json"]["schema"] = json!({"type":"object","required":["email"],"properties":{"email":{"type":"string"}}});
            }
            object.insert(method, operation);
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": { "title": "Kestrel API", "version": env!("CARGO_PKG_VERSION") },
        "paths": paths,
        "components":{"securitySchemes":{
            "session":{"type":"apiKey","in":"cookie","name":"kestrel_session"},
            "bearer":{"type":"http","scheme":"bearer"},
            "mutualTls":{"type":"mutualTLS"}
        }},
    })
}

fn auth_security(auth: AuthKind) -> Value {
    match auth {
        AuthKind::Public => json!([]),
        AuthKind::Agent => json!([{"mutualTls": []}]),
        AuthKind::User(_) => json!([{"session": []},{"bearer": []}]),
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    detail: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "type": "about:blank",
            "title": self.status.canonical_reason().unwrap_or("Error"),
            "status": self.status.as_u16(),
            "detail": self.detail,
        });
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        )
            .into_response()
    }
}

fn fail(status: StatusCode, detail: impl Into<String>) -> ApiError {
    ApiError {
        status,
        detail: detail.into(),
    }
}

struct AuthUser(Principal);

#[async_trait]
impl FromRequestParts<ApiState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let session = session_secret(&parts.headers);
        let token = bearer_token(&parts.headers);
        let session = if token.is_some() { None } else { session };
        if state.db.is_some() {
            return state
                .pg_principal(session.as_deref(), token.as_deref())
                .await?
                .map(AuthUser)
                .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "authentication required"));
        }
        state
            .catalog
            .principal(session.as_deref(), token.as_deref())
            .map(AuthUser)
            .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "authentication required"))
    }
}

fn ensure(principal: &Principal, permission: Permission) -> Result<(), ApiError> {
    if role_allows(&principal.role, permission) {
        Ok(())
    } else {
        Err(fail(StatusCode::FORBIDDEN, "not allowed"))
    }
}

#[derive(Debug, Deserialize, Default)]
struct Page {
    limit: Option<usize>,
    cursor: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AckBody {
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SwitchBody {
    tenant_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct MetricQuery {
    query: String,
    time: Option<i64>,
    start: Option<i64>,
    end: Option<i64>,
    step: Option<u32>,
}

async fn login(
    State(state): State<ApiState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Json(body): Json<LoginBody>,
) -> Result<Response, ApiError> {
    // Key failures on the address and the client, so nobody can lock another
    // user out by failing logins for their address from elsewhere.
    let throttle_key = format!(
        "{}|{}",
        body.email,
        peer.map(|info| info.0.ip().to_string()).unwrap_or_default()
    );
    if body.email.is_empty() || body.password.is_empty() {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "email and password are required",
        ));
    }
    if state.login_throttle.blocked(&throttle_key) {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed sign-in attempts; try again later",
        ));
    }
    let result = if state.db.is_some() {
        state.pg_login(&body.email, &body.password).await
    } else {
        state
            .catalog
            .login(&body.email, &body.password)
            .map_err(|_| fail(StatusCode::UNAUTHORIZED, "invalid email or password"))
    };
    match &result {
        Ok(_) => state.login_throttle.succeeded(&throttle_key),
        Err(err) if err.status == StatusCode::UNAUTHORIZED => {
            state.login_throttle.failed(&throttle_key)
        }
        Err(_) => {}
    }
    let secret = result?;
    let cookie = session_cookie(&secret, state.secure_cookie);
    let mut response = Json(json!({ "email": body.email })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .unwrap_or(HeaderValue::from_static("kestrel_session=; HttpOnly")),
    );
    Ok(response)
}

async fn logout(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(secret) = session_secret(&headers) {
        if state.db.is_some() {
            state.pg_logout(&principal, &secret).await?;
        } else {
            state.catalog.logout(&secret);
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("kestrel_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"),
    );
    Ok(response)
}

async fn openapi() -> Json<Value> {
    Json(openapi_value())
}

async fn list_hosts(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::HostRead, "host", page).await
}

fn uri_resource(
    uri: &axum::http::Uri,
    write: bool,
) -> Result<(&'static str, Permission), ApiError> {
    Ok(match (uri.path().split('/').nth(3).unwrap_or(""), write) {
        ("hosts", false) => ("host", Permission::HostRead),
        ("hosts", true) => ("host", Permission::HostWrite),
        ("host-groups", false) => ("host_group", Permission::GroupRead),
        ("host-groups", true) => ("host_group", Permission::GroupWrite),
        ("triggers", false) => ("trigger", Permission::TriggerRead),
        ("triggers", true) => ("trigger", Permission::TriggerWrite),
        ("actions", false) => ("action", Permission::ActionRead),
        ("actions", true) => ("action", Permission::ActionWrite),
        ("users", false) => ("user", Permission::UserRead),
        ("users", true) => ("user", Permission::AdminUsers),
        ("api-tokens", false) => ("token", Permission::UserRead),
        ("api-tokens", true) => ("token", Permission::AdminUsers),
        ("media-types", false) => ("media", Permission::MediaRead),
        ("media-types", true) => ("media", Permission::MediaWrite),
        ("templates", false) => ("template", Permission::TemplateRead),
        ("templates", true) => ("template", Permission::TemplateWrite),
        ("items", false) => ("item", Permission::TemplateRead),
        ("items", true) => ("item", Permission::TemplateWrite),
        ("discovery-rules", false) => ("discovery_rule", Permission::TemplateRead),
        ("discovery-rules", true) => ("discovery_rule", Permission::TemplateWrite),
        ("maintenances", false) => ("maintenance", Permission::MaintenanceRead),
        ("maintenances", true) => ("maintenance", Permission::MaintenanceWrite),
        ("dashboards", false) => ("dashboard", Permission::DashboardRead),
        ("dashboards", true) => ("dashboard", Permission::DashboardWrite),
        _ => return Err(fail(StatusCode::NOT_FOUND, "not found")),
    })
}
async fn create_enrolment_token(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::HostWrite)?;
    let directory = state
        .directory
        .as_ref()
        .ok_or_else(|| fail(StatusCode::SERVICE_UNAVAILABLE, "enrolment is unavailable"))?;
    let group = body
        .get("host_group_id")
        .map(|value| {
            value
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "invalid host_group_id"))
        })
        .transpose()?;
    if let Some(group) = group {
        if state.db.is_some() {
            state.pg_get(&principal, "host_group", group, false).await?;
        } else if state.catalog.get(&principal, "host_group", group).is_none() {
            return Err(fail(StatusCode::NOT_FOUND, "host group not found"));
        }
    }
    let ttl = body
        .get("ttl_seconds")
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value > 0 && *value <= 86400)
                .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "ttl_seconds must be 1..86400"))
        })
        .transpose()?
        .unwrap_or(3600);
    let token = directory
        .create_token_for(
            principal.tenant_id,
            group.map(|id| id.to_string()),
            std::time::Duration::from_secs(ttl),
        )
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "token creation failed"))?;
    if state.db.is_some() {
        state
            .pg_record_control(&principal, "enrolment_token.create", "agent")
            .await?;
    }
    Ok(Json(
        json!({"token":token,"tenant_id":principal.tenant_id,"ttl_seconds":ttl}),
    ))
}
async fn update_tenant(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::TenantAdmin)?;
    if state.db.is_some() {
        return state.pg_update_tenant(&principal, id, body).await.map(Json);
    }
    Err(fail(StatusCode::NOT_FOUND, "not found"))
}
async fn link_parent(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::TemplateWrite)?;
    let parent = body["parent_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "parent_id is required"))?;
    if state.db.is_some() {
        return state.pg_link_parent(&principal, id, parent).await.map(Json);
    }
    Err(fail(StatusCode::NOT_FOUND, "not found"))
}
async fn get_snmp(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::HostRead)?;
    if state.db.is_some() {
        return state.pg_snmp(&principal, id, None).await.map(Json);
    }
    Err(fail(StatusCode::NOT_FOUND, "not found"))
}
async fn put_snmp(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::HostWrite)?;
    if state.db.is_some() {
        return state.pg_snmp(&principal, id, Some(body)).await.map(Json);
    }
    Err(fail(StatusCode::NOT_FOUND, "not found"))
}
async fn get_resource(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Json<Value>, ApiError> {
    let (kind, permission) = uri_resource(&uri, false)?;
    get_kind(State(state), user, permission, kind, id).await
}
async fn update_resource(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let (kind, permission) = uri_resource(&uri, true)?;
    ensure(&principal, permission)?;
    if state.db.is_some() {
        return state.pg_update(&principal, kind, id, body).await.map(Json);
    }
    state
        .catalog
        .update(&principal, kind, id, body)
        .map(Json)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))
}
async fn delete_resource(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<StatusCode, ApiError> {
    let (kind, permission) = uri_resource(&uri, true)?;
    ensure(&principal, permission)?;
    if state.db.is_some() {
        state.pg_delete(&principal, kind, id).await?;
    } else if !state.catalog.delete(&principal, kind, id) {
        return Err(fail(StatusCode::NOT_FOUND, "not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn create_tenant(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::TenantAdmin)?;
    if state.db.is_some() {
        return state.pg_create_tenant(&principal, body).await.map(Json);
    }
    let name = body["name"]
        .as_str()
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "name is required"))?;
    let id = Uuid::new_v4();
    state
        .catalog
        .add_tenant(id, name, Some(principal.tenant_id));
    state.catalog.add_grant(principal.user_id, id);
    Ok(Json(
        json!({"id":id,"name":name,"parent_id":principal.tenant_id}),
    ))
}
async fn create_host(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::HostWrite, "host", body).await
}
async fn get_host(
    state: State<ApiState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    get_kind(state, user, Permission::HostRead, "host", id).await
}
async fn list_groups(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::GroupRead, "host_group", page).await
}
async fn create_group(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::GroupWrite, "host_group", body).await
}
async fn list_triggers(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::TriggerRead, "trigger", page).await
}
async fn create_trigger(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::TriggerWrite, "trigger", body).await
}
async fn list_problems(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::ProblemRead, "problem", page).await
}
async fn get_problem(
    state: State<ApiState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    get_kind(state, user, Permission::ProblemRead, "problem", id).await
}
async fn list_actions(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::ActionRead, "action", page).await
}
async fn create_action(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::ActionWrite, "action", body).await
}
async fn list_users(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::UserRead, "user", page).await
}
async fn create_user(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::AdminUsers, "user", body).await
}
async fn list_tokens(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::UserRead, "token", page).await
}
async fn create_token(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::AdminUsers, "token", body).await
}
async fn list_media(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::MediaRead, "media", page).await
}
async fn create_media(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::MediaWrite, "media", body).await
}
async fn list_dashboards(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::DashboardRead, "dashboard", page).await
}
async fn create_dashboard(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::DashboardWrite, "dashboard", body).await
}
async fn get_dashboard(
    state: State<ApiState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    get_kind(state, user, Permission::DashboardRead, "dashboard", id).await
}
async fn update_dashboard(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::DashboardWrite)?;
    if state.db.is_some() {
        return state
            .pg_update_dashboard(&principal, id, body)
            .await
            .map(Json);
    }
    state
        .catalog
        .update_dashboard(&principal, id, body)
        .map(Json)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))
}
async fn list_templates(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::TemplateRead, "template", page).await
}
async fn create_template(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::TemplateWrite, "template", body).await
}
async fn list_discovery_rules(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(
        state,
        user,
        Permission::TemplateRead,
        "discovery_rule",
        page,
    )
    .await
}
async fn create_discovery_rule(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(
        state,
        user,
        Permission::TemplateWrite,
        "discovery_rule",
        body,
    )
    .await
}
async fn list_items(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::TemplateRead, "item", page).await
}
async fn create_item(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(state, user, Permission::TemplateWrite, "item", body).await
}
async fn list_maintenances(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(
        state,
        user,
        Permission::MaintenanceRead,
        "maintenance",
        page,
    )
    .await
}
async fn create_maintenance(
    state: State<ApiState>,
    user: AuthUser,
    body: Json<Value>,
) -> Result<Json<Value>, ApiError> {
    create_kind(
        state,
        user,
        Permission::MaintenanceWrite,
        "maintenance",
        body,
    )
    .await
}
async fn list_tenants(
    state: State<ApiState>,
    user: AuthUser,
    page: Query<Page>,
) -> Result<Json<Value>, ApiError> {
    list_kind(state, user, Permission::TenantRead, "tenant", page).await
}

async fn list_kind(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    permission: Permission,
    kind: &str,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, permission)?;
    if state.db.is_some() {
        return state
            .pg_list(
                &principal,
                kind,
                page.limit.unwrap_or(50),
                page.cursor.as_deref(),
                page.status.as_deref(),
            )
            .await
            .map(Json);
    }
    Ok(Json(state.catalog.list_page(
        &principal,
        kind,
        page.limit.unwrap_or(50),
        page.cursor.as_deref(),
        page.status.as_deref(),
    )))
}

async fn create_kind(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    permission: Permission,
    kind: &str,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, permission)?;
    if state.db.is_some() {
        return state.pg_insert(&principal, kind, body).await.map(Json);
    }
    state
        .catalog
        .insert(&principal, kind, body)
        .map(Json)
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))
}

async fn get_kind(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    permission: Permission,
    kind: &str,
    id: Uuid,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, permission)?;
    if state.db.is_some() {
        return state.pg_get(&principal, kind, id, false).await.map(Json);
    }
    state
        .catalog
        .get(&principal, kind, id)
        .map(Json)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))
}

async fn ack_problem(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<AckBody>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::ProblemAck)?;
    let comment = body.comment.unwrap_or_default();
    let updated = if state.db.is_some() {
        state.pg_ack(&principal, id, &comment).await?
    } else {
        state
            .catalog
            .ack(&principal, id, &comment)
            .map_err(|_| fail(StatusCode::NOT_FOUND, "not found"))?
    };
    let _ = state.events.send(ProblemNote {
        tenant_id: principal.tenant_id,
        problem_id: id,
        kind: "acknowledged".to_string(),
    });
    Ok(Json(updated))
}

async fn create_step(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(mut body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::ActionWrite)?;
    if let Some(object) = body.as_object_mut() {
        object.insert("action_id".to_string(), json!(id));
    }
    if state.db.is_some() {
        return state
            .pg_insert(&principal, "action_step", body)
            .await
            .map(Json);
    }
    state
        .catalog
        .insert(&principal, "action_step", body)
        .map(Json)
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))
}

async fn test_media(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::MediaWrite)?;
    if state.db.is_some() {
        let media = state.pg_get(&principal, "media", id, true).await?;
        let mut target = media["config"].clone();
        target["kind"] = media["kind"].clone();
        target = crate::notify::with_smtp_defaults(target, state.smtp.as_ref());
        let rendered = crate::notify::render_for_target(
            "test", "test", "kestrel", "media", "1", "", "problem", &target,
        )
        .map_err(|_| {
            fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "template rendering failed",
            )
        })?;
        let result = if target["kind"] == "email" {
            crate::notify::send_smtp(&rendered, &target).await
        } else {
            crate::notify::HttpNotifier::guarded(state.egress.clone())
                .send(&rendered, &target)
                .await
        };
        result.map_err(|_| fail(StatusCode::BAD_GATEWAY, "test delivery failed"))?;
        state.pg_record_media_test(&principal, id).await?;
        return Ok(Json(json!({"ok":true})));
    }
    let media = state
        .catalog
        .get(&principal, "media", id)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))?;
    let url = media
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or("memory://local");
    if !url.starts_with("memory://") {
        let notifier = crate::notify::HttpNotifier::guarded(state.egress.clone());
        let rendered = crate::notify::render("test", "kestrel", "media", "1", url, "problem")
            .map_err(|err| fail(StatusCode::BAD_GATEWAY, err.to_string()))?;
        let target = json!({ "kind": media.get("kind").and_then(Value::as_str).unwrap_or("webhook"), "url": url, "webhook_url": url, "secret": media.get("secret").and_then(Value::as_str).unwrap_or("") });
        notifier
            .send(&rendered, &target)
            .await
            .map_err(|err| fail(StatusCode::BAD_GATEWAY, err.to_string()))?;
    }
    state
        .catalog
        .insert(
            &principal,
            "media_test",
            json!({ "media_id": id, "delivered": true }),
        )
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))?;
    Ok(Json(json!({ "ok": true })))
}

async fn export_template(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    ensure(&principal, Permission::TemplateRead)?;
    if state.db.is_some() {
        let doc = state.pg_export_template(&principal, id).await?;
        let yaml = crate::config_compile::template_to_yaml(&doc)
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "template export failed"))?;
        return Ok(([(header::CONTENT_TYPE, "application/yaml")], yaml).into_response());
    }
    let template = state
        .catalog
        .get(&principal, "template", id)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not found"))?;
    let yaml = serde_yaml::to_string(&template).unwrap_or_default();
    Ok(([(header::CONTENT_TYPE, "application/yaml")], yaml).into_response())
}

async fn import_template(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    body: String,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::TemplateWrite)?;
    let doc = crate::config_compile::template_from_yaml(&body)
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))?;
    if state.db.is_some() {
        return state.pg_import_template(&principal, doc).await.map(Json);
    }
    let template = state
        .catalog
        .insert(
            &principal,
            "template",
            json!({ "name": doc.name, "description": doc.description }),
        )
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))?;
    for item in doc.items {
        state
            .catalog
            .insert(
                &principal,
                "item",
                json!({
                    "template_id": template["id"],
                    "key": item.key,
                    "kind": item.kind,
                    "interval_s": item.interval_s,
                    "params": item.params,
                }),
            )
            .map_err(|err| fail(StatusCode::BAD_REQUEST, err))?;
    }
    Ok(Json(template))
}

async fn link_template(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::TemplateWrite)?;
    if state.db.is_some() {
        let template = body["template_id"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "template_id is required"))?;
        return state
            .pg_link_template(&principal, id, template)
            .await
            .map(Json);
    }
    state
        .catalog
        .insert(
            &principal,
            "template_link",
            json!({ "host_id": id, "template_id": body.get("template_id").cloned().unwrap_or(Value::Null) }),
        )
        .map(Json)
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))
}

async fn list_audit(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::AuditRead)?;
    if state.db.is_some() {
        return state.pg_audits(&principal).await.map(Json);
    }
    Ok(Json(state.catalog.audits(&principal)))
}

async fn query_instant(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Query(query): Query<MetricQuery>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::MetricsRead)?;
    let at = query.time.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let series = scoped_query(&state, &principal, &query.query, at, at, 0, true).await?;
    Ok(Json(json!({ "series": series })))
}

async fn query_range(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Query(query): Query<MetricQuery>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::MetricsRead)?;
    let start = query
        .start
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "start is required"))?;
    let end = query
        .end
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "end is required"))?;
    let step = query.step.unwrap_or(60);
    let series = scoped_query(&state, &principal, &query.query, start, end, step, false).await?;
    Ok(Json(json!({ "series": series })))
}

async fn scoped_query(
    state: &ApiState,
    principal: &Principal,
    query: &str,
    start: i64,
    end: i64,
    step: u32,
    instant: bool,
) -> Result<Vec<Value>, ApiError> {
    let hosts = if state.db.is_some() {
        state.pg_host_names(principal).await?
    } else {
        state.catalog.host_names(principal)
    };
    let scoped = inject_scope(query, &principal.tenant_id.to_string(), hosts.as_deref())
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))?;
    let series = if instant {
        state
            .store
            .query(&scoped, end)
            .await
            .map_err(|err| fail(StatusCode::BAD_GATEWAY, err.to_string()))?
    } else {
        state
            .store
            .query_range(&scoped, start, end, step)
            .await
            .map_err(|err| fail(StatusCode::BAD_GATEWAY, err.to_string()))?
    };
    let tenant = principal.tenant_id.to_string();
    let mut out = Vec::new();
    for item in series {
        let tenant_ok = item
            .labels
            .iter()
            .filter(|(name, _)| name == "tenant")
            .all(|(_, value)| value == &tenant);
        let host_ok = match &hosts {
            None => true,
            Some(hosts) => item
                .labels
                .iter()
                .filter(|(name, _)| name == "host")
                .all(|(_, value)| hosts.iter().any(|host| host == value)),
        };
        if tenant_ok && host_ok {
            out.push(json!({ "labels": item.labels, "points": item.points }));
        }
    }
    Ok(out)
}

async fn event_permitted(
    state: &ApiState,
    session: Option<&str>,
    bearer: Option<&str>,
    note: &ProblemNote,
) -> bool {
    let principal = if state.db.is_some() {
        match state.pg_principal(session, bearer).await {
            Ok(Some(principal)) => principal,
            _ => return false,
        }
    } else {
        let Some(principal) = state.catalog.principal(session, bearer) else {
            return false;
        };
        principal
    };
    if principal.tenant_id != note.tenant_id
        || !role_allows(&principal.role, Permission::ProblemRead)
    {
        return false;
    }
    if state.db.is_some() {
        state
            .pg_get(&principal, "problem", note.problem_id, false)
            .await
            .is_ok()
    } else {
        state
            .catalog
            .get(&principal, "problem", note.problem_id)
            .is_some()
    }
}

async fn event_stream(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    headers: HeaderMap,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    ensure(&principal, Permission::ProblemRead)?;
    let bearer = bearer_token(&headers);
    let session = if bearer.is_some() {
        None
    } else {
        session_secret(&headers)
    };
    let stream = futures::StreamExt::filter_map(
        tokio_stream::wrappers::BroadcastStream::new(state.events.subscribe()),
        move |item| {
            let state = state.clone();
            let session = session.clone();
            let bearer = bearer.clone();
            async move {
                let note = item.ok()?;
                if event_permitted(&state, session.as_deref(), bearer.as_deref(), &note).await {
                    Event::default().json_data(&note).ok().map(Ok)
                } else {
                    None
                }
            }
        },
    );
    Ok(Sse::new(stream))
}

async fn switch_tenant(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    headers: HeaderMap,
    Json(body): Json<SwitchBody>,
) -> Result<StatusCode, ApiError> {
    ensure(&principal, Permission::TenantRead)?;
    let secret = session_secret(&headers)
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "authentication required"))?;
    if state.db.is_some() {
        state.pg_switch(&principal, &secret, body.tenant_id).await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    state
        .catalog
        .switch_tenant(&secret, body.tenant_id)
        .map_err(|_| fail(StatusCode::FORBIDDEN, "not allowed"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn msp_overview(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::MspRead)?;
    if state.db.is_some() {
        return state.pg_overview(&principal).await.map(Json);
    }
    Ok(Json(state.catalog.msp_overview(&principal)))
}

async fn create_grant(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::TenantAdmin)?;
    let user_id = body
        .get("user_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "user_id is required"))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "tenant_id is required"))?;
    if state.db.is_some() {
        return state
            .pg_grant(
                &principal,
                user_id,
                tenant_id,
                body["role"].as_str().unwrap_or("viewer"),
            )
            .await
            .map(Json);
    }
    state.catalog.add_grant(user_id, tenant_id);
    state
        .catalog
        .insert(
            &principal,
            "grant",
            json!({ "user_id": user_id, "tenant_id": tenant_id }),
        )
        .map(Json)
        .map_err(|err| fail(StatusCode::BAD_REQUEST, err))
}

async fn delete_grant(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    Json(body): Json<Value>,
) -> Result<StatusCode, ApiError> {
    ensure(&principal, Permission::TenantAdmin)?;
    let user_id = body
        .get("user_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "user_id is required"))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "tenant_id is required"))?;
    if state.db.is_some() {
        state
            .pg_revoke_grant(&principal, user_id, tenant_id)
            .await?;
    } else {
        state.catalog.remove_grant(user_id, tenant_id);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn otlp_metrics(
    State(state): State<ApiState>,
    AuthUser(principal): AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    ensure(&principal, Permission::OtlpWrite)?;
    let drop_names: Vec<&str> = state.otlp_drop.iter().map(String::as_str).collect();
    let content = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json");
    let samples = if content.contains("protobuf") {
        samples_from_protobuf(&body, &drop_names)
            .map_err(|err| fail(StatusCode::BAD_REQUEST, err))?
    } else {
        let text = std::str::from_utf8(&body)
            .map_err(|_| fail(StatusCode::BAD_REQUEST, "body is not utf-8"))?;
        samples_from_json(text, &drop_names).map_err(|err| fail(StatusCode::BAD_REQUEST, err))?
    };
    let mut labelled = Vec::new();
    let allowed_hosts = if state.db.is_some() {
        state.pg_host_names(&principal).await?
    } else {
        state.catalog.host_names(&principal)
    };
    for sample in samples {
        let mut labels: Vec<(String, String)> = sample
            .labels
            .into_iter()
            .filter(|(name, _)| name != "tenant")
            .collect();
        labels.push(("tenant".to_string(), principal.tenant_id.to_string()));
        if let Some(hosts) = &allowed_hosts {
            if !labels
                .iter()
                .any(|(name, value)| name == "host" && hosts.contains(value))
            {
                return Err(fail(StatusCode::FORBIDDEN, "host is outside your scope"));
            }
        }
        labelled.push(LabelledSample {
            name: sample.name,
            labels,
            value: sample.value,
            timestamp_ms: sample.timestamp_ms,
        });
    }
    let count = labelled.len();
    let rate = if let Some(db) = &state.db {
        sqlx::query_scalar::<_, i32>("SELECT samples_per_second FROM tenants WHERE id=$1")
            .bind(principal.tenant_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "quota lookup failed"))?
            .max(0) as u32
    } else {
        50_000
    };
    if count > 0
        && state
            .quotas
            .check_with_rate(
                principal.tenant_id,
                u32::try_from(count).unwrap_or(u32::MAX),
                rate,
            )
            .is_err()
    {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "sample quota exceeded"));
    }
    state
        .store
        .write(labelled)
        .await
        .map_err(|err| fail(StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(json!({ "accepted": count })))
}

fn session_secret(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    memory::read_cookie(value, SESSION_COOKIE)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.starts_with("kst_") {
        Some(token.to_string())
    } else {
        None
    }
}

pub fn event_visible(event_tenant: Uuid, principal_tenant: Uuid) -> bool {
    event_tenant == principal_tenant
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use axum::http::StatusCode;

    fn state_with(role: &str) -> (ApiState, String) {
        let tenant = Uuid::from_u128(11);
        let catalog = Arc::new(MemoryCatalog::new());
        catalog.add_tenant(tenant, "acme", None);
        catalog
            .add_user(tenant, "owner@example.com", "correct-horse", "owner", None)
            .unwrap();
        catalog
            .add_user(
                tenant,
                "viewer@example.com",
                "correct-horse",
                "viewer",
                None,
            )
            .unwrap();
        let store = Arc::new(MemoryStore::new());
        let state = ApiState::new(catalog, store);
        let email = if role == "viewer" {
            "viewer@example.com"
        } else {
            "owner@example.com"
        };
        (state, email.to_string())
    }

    async fn signed_in(role: &str) -> axum_test::TestServer {
        let (state, email) = state_with(role);
        let mut server = axum_test::TestServer::builder()
            .save_cookies()
            .build(router(state))
            .unwrap();
        server.save_cookies();
        let response = server
            .post("/api/v1/login")
            .json(&json!({ "email": email, "password": "correct-horse" }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
        server
    }

    #[tokio::test]
    async fn api_login_and_host_crud_do_not_echo_secrets() {
        let server = signed_in("owner").await;
        let wrong = server
            .post("/api/v1/login")
            .json(&json!({ "email": "owner@example.com", "password": "not-the-password" }))
            .await;
        assert_eq!(wrong.status_code(), StatusCode::UNAUTHORIZED);
        assert!(!wrong.text().contains("not-the-password"));
        assert!(!wrong.text().contains("correct-horse"));
        let created = server
            .post("/api/v1/hosts")
            .json(&json!({ "name": "web-1" }))
            .await;
        created.assert_status_ok();
        let id = created.json::<Value>()["id"].as_str().unwrap().to_string();
        let listed = server.get("/api/v1/hosts").await.json::<Value>();
        assert!(listed["items"].to_string().contains("web-1"));
        server
            .get(&format!("/api/v1/hosts/{id}"))
            .await
            .assert_status_ok();
        let audit = server.get("/api/v1/audit").await.json::<Value>();
        assert!(audit["items"].to_string().contains("host.create"));
        let anon = axum_test::TestServer::builder()
            .save_cookies()
            .build(router(state_with("owner").0))
            .unwrap();
        assert_eq!(
            anon.get("/api/v1/hosts").await.status_code(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn authz_viewer_is_forbidden_on_every_write_route() {
        let server = signed_in("viewer").await;
        for spec in ROUTES {
            let AuthKind::User(permission) = spec.auth else {
                continue;
            };
            if !matches!(spec.location, Location::Api) || role_allows("viewer", permission) {
                continue;
            }
            let path = spec.path.replace("{id}", &Uuid::nil().to_string());
            let response = match spec.method {
                "POST" => server.post(&path).json(&json!({})).await,
                "GET" => server.get(&path).await,
                _ => continue,
            };
            assert_eq!(
                response.status_code(),
                StatusCode::FORBIDDEN,
                "{} {}",
                spec.method,
                spec.path
            );
        }
    }

    #[tokio::test]
    async fn authz_openapi_lists_every_route() {
        let server = signed_in("owner").await;
        let document = server.get("/api/v1/openapi.json").await.json::<Value>();
        let paths = document["paths"].as_object().unwrap();
        for spec in ROUTES {
            assert!(paths.contains_key(spec.path), "missing {}", spec.path);
        }
        let _ = router(state_with("owner").0);
    }

    #[tokio::test]
    async fn api_metric_proxy_keeps_the_other_tenant_out() {
        let tenant_a = Uuid::from_u128(11);
        let tenant_b = Uuid::from_u128(22);
        let catalog = Arc::new(MemoryCatalog::new());
        catalog.add_tenant(tenant_a, "a", None);
        catalog.add_tenant(tenant_b, "b", None);
        catalog
            .add_user(tenant_a, "a@example.com", "correct-horse", "owner", None)
            .unwrap();
        let store = Arc::new(MemoryStore::new());
        store
            .write(vec![
                LabelledSample {
                    name: "up".to_string(),
                    labels: vec![
                        ("tenant".to_string(), tenant_a.to_string()),
                        ("host".to_string(), "web".to_string()),
                    ],
                    value: 1.0,
                    timestamp_ms: 1_700_000_000_000,
                },
                LabelledSample {
                    name: "up".to_string(),
                    labels: vec![
                        ("tenant".to_string(), tenant_b.to_string()),
                        ("host".to_string(), "secret".to_string()),
                    ],
                    value: 1.0,
                    timestamp_ms: 1_700_000_000_000,
                },
            ])
            .await
            .unwrap();
        let mut server = axum_test::TestServer::builder()
            .save_cookies()
            .build(router(ApiState::new(catalog, store)))
            .unwrap();
        server.save_cookies();
        server
            .post("/api/v1/login")
            .json(&json!({ "email": "a@example.com", "password": "correct-horse" }))
            .await
            .assert_status_ok();
        let body = server
            .get("/api/v1/metrics/query_range")
            .add_query_param("query", "up")
            .add_query_param("start", "1699999000")
            .add_query_param("end", "1700001000")
            .add_query_param("step", "60")
            .await
            .json::<Value>();
        let text = body.to_string();
        assert!(text.contains(&tenant_a.to_string()), "{text}");
        assert!(!text.contains(&tenant_b.to_string()), "{text}");
        assert!(!text.contains("secret"), "{text}");
        assert!(event_visible(tenant_a, tenant_a));
        assert!(!event_visible(tenant_b, tenant_a));
    }
}
