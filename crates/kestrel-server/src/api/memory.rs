//! In-memory API catalogue. Every read and write filters on `tenant_id`.

use crate::authz::{group_visible, scope_for};
use crate::passwords::{hash_password, random_token, token_hash, verify_password};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub host_group_id: Option<Uuid>,
    pub email: String,
}

/// Login or tenant switch was refused. The reason is not returned to callers.
#[derive(Debug)]
pub struct Rejected;

struct UserRow {
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    password_hash: String,
    role: String,
    host_group_id: Option<Uuid>,
}

struct SessionRow {
    user_id: Uuid,
    tenant_id: Uuid,
}

struct TokenRow {
    user_id: Uuid,
    tenant_id: Uuid,
}

struct Row {
    id: Uuid,
    tenant_id: Uuid,
    kind: String,
    group_id: Option<Uuid>,
    body: Value,
}

struct AuditRow {
    tenant_id: Uuid,
    user_id: Uuid,
    action: String,
    target: String,
}

struct Grant {
    user_id: Uuid,
    tenant_id: Uuid,
}

struct TenantRow {
    id: Uuid,
    name: String,
    parent_id: Option<Uuid>,
}

struct Inner {
    users: Vec<UserRow>,
    sessions: HashMap<String, SessionRow>,
    tokens: HashMap<String, TokenRow>,
    rows: Vec<Row>,
    audits: Vec<AuditRow>,
    grants: Vec<Grant>,
    tenants: Vec<TenantRow>,
}

pub struct MemoryCatalog {
    inner: Mutex<Inner>,
}

impl MemoryCatalog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                users: Vec::new(),
                sessions: HashMap::new(),
                tokens: HashMap::new(),
                rows: Vec::new(),
                audits: Vec::new(),
                grants: Vec::new(),
                tenants: Vec::new(),
            }),
        }
    }

    pub fn add_tenant(&self, id: Uuid, name: &str, parent_id: Option<Uuid>) {
        let mut inner = self.lock();
        inner.tenants.push(TenantRow {
            id,
            name: name.to_string(),
            parent_id,
        });
    }

    pub fn add_user(
        &self,
        tenant_id: Uuid,
        email: &str,
        password: &str,
        role: &str,
        host_group_id: Option<Uuid>,
    ) -> Result<Uuid, String> {
        let hash = hash_password(password).map_err(|err| err.to_string())?;
        let id = Uuid::new_v4();
        self.lock().users.push(UserRow {
            id,
            tenant_id,
            email: email.to_string(),
            password_hash: hash,
            role: role.to_string(),
            host_group_id,
        });
        Ok(id)
    }

    pub fn add_grant(&self, user_id: Uuid, tenant_id: Uuid) {
        self.lock().grants.push(Grant { user_id, tenant_id });
    }

    pub fn login(&self, email: &str, password: &str) -> Result<String, Rejected> {
        let mut inner = self.lock();
        let found = inner
            .users
            .iter()
            .find(|user| user.email == email)
            .map(|user| (user.id, user.tenant_id, user.password_hash.clone()));
        let Some((user_id, tenant_id, hash)) = found else {
            let _ = verify_password(password, "");
            return Err(Rejected);
        };
        if !verify_password(password, &hash) {
            return Err(Rejected);
        }
        let secret = random_token("sess_").map_err(|_| Rejected)?;
        inner
            .sessions
            .insert(token_hash(&secret), SessionRow { user_id, tenant_id });
        Ok(secret)
    }

    pub fn logout(&self, secret: &str) {
        self.lock().sessions.remove(&token_hash(secret));
    }

    pub fn principal(&self, session: Option<&str>, bearer: Option<&str>) -> Option<Principal> {
        let inner = self.lock();
        if let Some(secret) = session {
            if let Some(row) = inner.sessions.get(&token_hash(secret)) {
                return user_principal(&inner, row.user_id, row.tenant_id);
            }
        }
        if let Some(token) = bearer {
            if let Some(row) = inner.tokens.get(&token_hash(token)) {
                return user_principal(&inner, row.user_id, row.tenant_id);
            }
        }
        None
    }

    pub fn switch_tenant(&self, secret: &str, tenant_id: Uuid) -> Result<(), Rejected> {
        let mut inner = self.lock();
        let hash = token_hash(secret);
        let user_id = inner
            .sessions
            .get(&hash)
            .map(|session| session.user_id)
            .ok_or(Rejected)?;
        let home = inner
            .users
            .iter()
            .find(|user| user.id == user_id)
            .map(|user| user.tenant_id)
            .ok_or(Rejected)?;
        let allowed = home == tenant_id
            || inner
                .grants
                .iter()
                .any(|grant| grant.user_id == user_id && grant.tenant_id == tenant_id);
        if !allowed {
            return Err(Rejected);
        }
        inner
            .sessions
            .insert(hash, SessionRow { user_id, tenant_id });
        Ok(())
    }

    pub fn list_page(
        &self,
        principal: &Principal,
        kind: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Value {
        let limit = limit.clamp(1, 200);
        let mut items = self.visible(principal, kind);
        if let Some(cursor) = cursor {
            if let Some(pos) = items
                .iter()
                .position(|row| row["id"].as_str() == Some(cursor))
            {
                items = items.split_off(pos.saturating_add(1));
            }
        }
        let next = if items.len() > limit {
            items[limit - 1]["id"].clone()
        } else {
            Value::Null
        };
        items.truncate(limit);
        json!({ "items": items, "next": next })
    }

    pub fn get(&self, principal: &Principal, kind: &str, id: Uuid) -> Option<Value> {
        self.visible(principal, kind)
            .into_iter()
            .find(|row| row["id"].as_str() == Some(&id.to_string()))
    }

    pub fn insert(
        &self,
        principal: &Principal,
        kind: &str,
        mut body: Value,
    ) -> Result<Value, String> {
        if body.get("password").is_some() && kind == "user" {
            let password = body
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let hash = hash_password(&password).map_err(|err| err.to_string())?;
            if let Some(object) = body.as_object_mut() {
                object.remove("password");
                object.insert("password_hash".to_string(), Value::String(hash));
            }
        }
        let mut revealed = None;
        if kind == "token" {
            let secret = random_token("kst_").map_err(|err| err.to_string())?;
            let hash = token_hash(&secret);
            self.lock().tokens.insert(
                hash.clone(),
                TokenRow {
                    user_id: principal.user_id,
                    tenant_id: principal.tenant_id,
                },
            );
            if let Some(object) = body.as_object_mut() {
                object.insert("token_hash".to_string(), Value::String(hash));
            }
            revealed = Some(secret);
        }
        let id = Uuid::new_v4();
        if kind == "user" {
            let email = body
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let role = body
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("viewer")
                .to_string();
            let password_hash = body
                .get("password_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let host_group_id = body
                .get("host_group_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            if email.is_empty() || password_hash.is_empty() {
                return Err("email and password are required".to_string());
            }
            self.lock().users.push(UserRow {
                id,
                tenant_id: principal.tenant_id,
                email,
                password_hash,
                role,
                host_group_id,
            });
        }
        let group_id = body
            .get("host_group_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .or_else(|| {
                body.get("host_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .and_then(|host_id| self.group_of_host(principal.tenant_id, host_id))
            });
        if let Some(object) = body.as_object_mut() {
            object.insert("id".to_string(), json!(id));
            object.insert("tenant_id".to_string(), json!(principal.tenant_id));
            object.insert("kind".to_string(), json!(kind));
        }
        self.lock().rows.push(Row {
            id,
            tenant_id: principal.tenant_id,
            kind: kind.to_string(),
            group_id,
            body: body.clone(),
        });
        self.audit(principal, &format!("{kind}.create"), &id.to_string());
        if let Some(secret) = revealed {
            if let Some(object) = body.as_object_mut() {
                object.insert("token".to_string(), Value::String(secret));
            }
        }
        if kind == "user" {
            if let Some(object) = body.as_object_mut() {
                object.remove("password_hash");
            }
        }
        Ok(body)
    }

    pub fn ack(&self, principal: &Principal, id: Uuid, comment: &str) -> Result<Value, String> {
        let mut inner = self.lock();
        let row = inner
            .rows
            .iter_mut()
            .find(|row| {
                row.kind == "problem" && row.id == id && row.tenant_id == principal.tenant_id
            })
            .ok_or_else(|| "problem not found".to_string())?;
        if !group_visible(
            &scope_for(
                principal.tenant_id,
                &principal.role,
                principal.host_group_id,
            ),
            row.group_id,
        ) {
            return Err("problem not found".to_string());
        }
        if let Some(object) = row.body.as_object_mut() {
            object.insert("status".to_string(), json!("problem"));
            object.insert("acknowledged".to_string(), json!(true));
            object.insert("comment".to_string(), json!(comment));
        }
        let body = row.body.clone();
        drop(inner);
        self.audit(principal, "problem.ack", &id.to_string());
        Ok(body)
    }

    pub fn audits(&self, principal: &Principal) -> Value {
        let inner = self.lock();
        let items: Vec<Value> = inner
            .audits
            .iter()
            .filter(|row| row.tenant_id == principal.tenant_id)
            .map(|row| {
                json!({
                    "action": row.action,
                    "target": row.target,
                    "user_id": row.user_id,
                    "tenant_id": row.tenant_id,
                })
            })
            .collect();
        json!({ "items": items })
    }

    pub fn msp_overview(&self, principal: &Principal) -> Value {
        let inner = self.lock();
        let items: Vec<Value> = inner
            .grants
            .iter()
            .filter(|grant| grant.user_id == principal.user_id)
            .filter_map(|grant| {
                inner
                    .tenants
                    .iter()
                    .find(|tenant| tenant.id == grant.tenant_id)
                    .map(|tenant| {
                        json!({
                            "tenant_id": tenant.id,
                            "name": tenant.name,
                            "parent_id": tenant.parent_id,
                        })
                    })
            })
            .collect();
        json!({ "items": items })
    }

    pub fn host_names(&self, principal: &Principal) -> Option<Vec<String>> {
        let scope = scope_for(
            principal.tenant_id,
            &principal.role,
            principal.host_group_id,
        );
        let groups = scope.groups.as_ref()?;
        let inner = self.lock();
        Some(
            inner
                .rows
                .iter()
                .filter(|row| row.kind == "host" && row.tenant_id == principal.tenant_id)
                .filter(|row| row.group_id.is_some_and(|id| groups.contains(&id)))
                .filter_map(|row| {
                    row.body
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect(),
        )
    }

    pub fn audit_contains_secret(&self, principal: &Principal, needle: &str) -> bool {
        let inner = self.lock();
        inner
            .audits
            .iter()
            .filter(|row| row.tenant_id == principal.tenant_id)
            .any(|row| row.action.contains(needle) || row.target.contains(needle))
            || inner.rows.iter().any(|row| {
                row.tenant_id == principal.tenant_id
                    && row.body.to_string().contains(needle)
                    && row.kind == "audit"
            })
    }

    fn group_of_host(&self, tenant_id: Uuid, host_id: Uuid) -> Option<Uuid> {
        self.lock().rows.iter().find_map(|row| {
            if row.kind == "host" && row.tenant_id == tenant_id && row.id == host_id {
                row.group_id
            } else {
                None
            }
        })
    }

    fn visible(&self, principal: &Principal, kind: &str) -> Vec<Value> {
        let scope = scope_for(
            principal.tenant_id,
            &principal.role,
            principal.host_group_id,
        );
        let inner = self.lock();
        inner
            .rows
            .iter()
            .filter(|row| row.tenant_id == principal.tenant_id && row.kind == kind)
            .filter(|row| {
                group_visible(&scope, row.group_id)
                    || row.group_id.is_none() && scope.groups.is_none()
            })
            .filter(|row| {
                if scope.groups.is_some() && matches!(kind, "host" | "problem") {
                    group_visible(&scope, row.group_id)
                } else {
                    true
                }
            })
            .map(|row| public_body(&row.body))
            .collect()
    }

    fn audit(&self, principal: &Principal, action: &str, target: &str) {
        self.lock().audits.push(AuditRow {
            tenant_id: principal.tenant_id,
            user_id: principal.user_id,
            action: action.to_string(),
            target: target.to_string(),
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl Default for MemoryCatalog {
    fn default() -> Self {
        Self::new()
    }
}

fn user_principal(inner: &Inner, user_id: Uuid, tenant_id: Uuid) -> Option<Principal> {
    let user = inner.users.iter().find(|user| user.id == user_id)?;
    Some(Principal {
        user_id: user.id,
        tenant_id,
        role: user.role.clone(),
        host_group_id: user.host_group_id,
        email: user.email.clone(),
    })
}

fn public_body(body: &Value) -> Value {
    let mut body = body.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("password");
        object.remove("password_hash");
        object.remove("token");
        object.remove("token_hash");
    }
    body
}

pub fn session_cookie(secret: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("kestrel_session={secret}; HttpOnly; SameSite=Lax; Path=/{secure}")
}

pub fn read_cookie(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        if key == name {
            Some(value.to_string())
        } else {
            None
        }
    })
}
