use super::*;

async fn sign_in(
    state: &ApiState,
    email: &str,
    password: &str,
    tenant: Option<&str>,
) -> LoginOutcome {
    state
        .pg_login(&LoginAttempt {
            email,
            password,
            tenant,
            source: Some("192.0.2.10".parse().unwrap()),
        })
        .await
        .unwrap()
}

async fn session_for(
    state: &ApiState,
    email: &str,
    password: &str,
    tenant: Option<&str>,
) -> String {
    match sign_in(state, email, password, tenant).await {
        LoginOutcome::Session(secret) => secret,
        _ => panic!("sign-in refused"),
    }
}

#[tokio::test]
async fn api_postgres_persists_auth_crud_templates_and_isolates_tenants() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let db = crate::db::Db::connect(&url).await.unwrap();
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();
    for id in [tenant, other] {
        sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
            .bind(id)
            .bind(format!("api-test-{id}"))
            .execute(&db.pool)
            .await
            .unwrap();
    }
    let email = format!("{tenant}@example.test");
    let user = db
        .insert_user(
            &crate::db::TenantId(tenant),
            crate::db::NewUser {
                email: email.clone(),
                password_hash: crate::passwords::hash_password("password-test").unwrap(),
                role: "owner".into(),
                host_group_id: None,
            },
        )
        .await
        .unwrap();
    let principal = Principal {
        user_id: user.id,
        tenant_id: tenant,
        email: email.clone(),
        role: "owner".into(),
        host_group_id: None,
    };
    let dir = std::env::temp_dir().join(format!("kestrel-api-pg-{tenant}"));
    let secrets =
        Arc::new(crate::secrets::SecretBox::load_or_create(&dir.join("secret.key")).unwrap());
    let state = ApiState::new(
        Arc::new(MemoryCatalog::new()),
        Arc::new(crate::MemoryStore::new()),
    )
    .with_database(db.clone(), Arc::clone(&secrets));
    assert!(matches!(
        sign_in(&state, &email, "wrong-password", None).await,
        LoginOutcome::Refused
    ));
    let session = session_for(&state, &email, "password-test", None).await;
    let authenticated = state
        .pg_principal(Some(&session), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authenticated.user_id, user.id);
    let group = state
        .pg_insert(&principal, "host_group", json!({"name":"group"}))
        .await
        .unwrap();
    let host = state
        .pg_insert(
            &principal,
            "host",
            json!({"name":"web-1","host_group_id":group["id"]}),
        )
        .await
        .unwrap();
    let host_id = Uuid::parse_str(host["id"].as_str().unwrap()).unwrap();
    let trigger: Uuid = sqlx::query_scalar("INSERT INTO triggers (tenant_id,host_id,name,expression,severity) VALUES ($1,$2,'CPU saturated','up == 0','high') RETURNING id")
        .bind(tenant).bind(host_id).fetch_one(&db.pool).await.unwrap();
    for status in ["problem", "resolved"] {
        sqlx::query("INSERT INTO problems (tenant_id,trigger_id,host_id,status,severity) VALUES ($1,$2,$3,$4,'high')")
            .bind(tenant).bind(trigger).bind(host_id).bind(status).execute(&db.pool).await.unwrap();
    }
    let open = state
        .pg_list(&principal, "problem", 50, None, Some("problem"))
        .await
        .unwrap();
    assert_eq!(open["items"].as_array().unwrap().len(), 1);
    assert_eq!(open["items"][0]["name"], "CPU saturated on web-1");
    assert_eq!(
        state
            .pg_list(&principal, "problem", 50, None, None)
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let dashboard = state
        .pg_insert(
            &principal,
            "dashboard",
            json!({"name":"Overview","layout":{"widgets":[]}}),
        )
        .await
        .unwrap();
    let dashboard_id = Uuid::parse_str(dashboard["id"].as_str().unwrap()).unwrap();
    state
        .pg_update_dashboard(
            &principal,
            dashboard_id,
            json!({"name":"Updated","layout":{"widgets":[{"kind":"stat"}]}}),
        )
        .await
        .unwrap();
    let restarted = ApiState::new(
        Arc::new(MemoryCatalog::new()),
        Arc::new(crate::MemoryStore::new()),
    )
    .with_database(db.clone(), Arc::clone(&secrets));
    assert!(restarted
        .pg_principal(Some(&session), None)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        restarted
            .pg_get(&principal, "dashboard", dashboard_id, false)
            .await
            .unwrap()["name"],
        "Updated"
    );
    let token = state
        .pg_insert(&principal, "token", json!({"name":"automation"}))
        .await
        .unwrap();
    assert!(restarted
        .pg_principal(None, token["token"].as_str())
        .await
        .unwrap()
        .is_some());
    assert!(state
        .pg_list(&principal, "token", 50, None, None)
        .await
        .unwrap()
        .to_string()
        .find("kst_")
        .is_none());
    let media=state.pg_insert(&principal,"media",json!({"name":"Webhook","kind":"webhook","config":{"url":"https://example.test/never-log-this","secret":"not-a-real-secret"}})).await.unwrap();
    let media_id = Uuid::parse_str(media["id"].as_str().unwrap()).unwrap();
    let stored: Value =
        sqlx::query_scalar("SELECT config FROM media_types WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(media_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(!stored.to_string().contains("never-log-this"));
    assert!(state
        .pg_get(&principal, "media", media_id, false)
        .await
        .unwrap()
        .get("config")
        .is_none());
    assert_eq!(
        state
            .pg_get(&principal, "media", media_id, true)
            .await
            .unwrap()["config"]["secret"],
        "not-a-real-secret"
    );
    let mut outsider = principal.clone();
    outsider.tenant_id = other;
    assert!(state
        .pg_get(&outsider, "host", host_id, false)
        .await
        .is_err());
    assert!(state
        .pg_update(&outsider, "host", host_id, json!({"name":"stolen"}))
        .await
        .is_err());
    let mut scoped = principal.clone();
    scoped.role = "operator".into();
    scoped.host_group_id = Some(Uuid::new_v4());
    assert_eq!(
        state
            .pg_list(&scoped, "host", 50, None, None)
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    scoped.host_group_id = Some(Uuid::parse_str(group["id"].as_str().unwrap()).unwrap());
    assert_eq!(
        state
            .pg_list(&scoped, "host", 50, None, None)
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(state
        .pg_get(&scoped, "dashboard", dashboard_id, false)
        .await
        .is_ok());
    let doc = crate::config_compile::builtin_templates().remove(0);
    let imported = state
        .pg_import_template(&principal, doc.clone())
        .await
        .unwrap();
    let imported_id = Uuid::parse_str(imported["id"].as_str().unwrap()).unwrap();
    let exported = state
        .pg_export_template(&principal, imported_id)
        .await
        .unwrap();
    assert_eq!(doc.name, exported.name);
    assert_eq!(doc.items.len(), exported.items.len());
    assert_eq!(doc.triggers.len(), exported.triggers.len());
    state
        .pg_link_template(&principal, host_id, imported_id)
        .await
        .unwrap();
    let (agent_cfg, _) = db
        .linked_agent_config(tenant, host_id, "web-1".into())
        .await
        .unwrap();
    assert!(!agent_cfg.items.is_empty());
    assert!(state
        .pg_grant(&principal, user.id, other, "viewer")
        .await
        .is_err());
    let child = state
        .pg_create_tenant(&principal, json!({"name":format!("child-{tenant}")}))
        .await
        .unwrap();
    let child_id = Uuid::parse_str(child["id"].as_str().unwrap()).unwrap();
    let event_trigger = state
        .pg_insert(
            &principal,
            "trigger",
            json!({"name":"SSE regression","expression":"up > 0","host_id":host_id}),
        )
        .await
        .unwrap();
    let event_problem = state
        .pg_insert(
            &principal,
            "problem",
            json!({"trigger_id":event_trigger["id"],"host_id":host_id}),
        )
        .await
        .unwrap();
    let note = ProblemNote {
        tenant_id: tenant,
        problem_id: Uuid::parse_str(event_problem["id"].as_str().unwrap()).unwrap(),
        kind: "opened".into(),
    };
    assert!(event_permitted(&state, Some(&session), None, &note).await);
    let different_group = state
        .pg_insert(&principal, "host_group", json!({"name":"other-group"}))
        .await
        .unwrap();
    sqlx::query("UPDATE users SET role='viewer',host_group_id=$2 WHERE id=$1")
        .bind(user.id)
        .bind(Uuid::parse_str(different_group["id"].as_str().unwrap()).unwrap())
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        !event_permitted(&state, Some(&session), None, &note).await,
        "an existing stream must observe group revocation"
    );
    sqlx::query("UPDATE users SET role='owner',host_group_id=NULL WHERE id=$1")
        .bind(user.id)
        .execute(&db.pool)
        .await
        .unwrap();
    state
        .pg_switch(&principal, &session, child_id)
        .await
        .unwrap();
    let child_principal = state
        .pg_principal(Some(&session), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(child_principal.role, "admin");
    assert_eq!(child_principal.tenant_id, child_id);
    assert!(
        !event_permitted(&state, Some(&session), None, &note).await,
        "tenant switching must revoke old stream visibility"
    );
    state
        .pg_switch(&child_principal, &session, tenant)
        .await
        .unwrap();
    state.pg_logout(&principal, &session).await.unwrap();
    assert!(
        !event_permitted(&state, Some(&session), None, &note).await,
        "logout must revoke an existing stream"
    );
    assert!(state
        .pg_principal(Some(&session), None)
        .await
        .unwrap()
        .is_none());
    let server = axum_test::TestServer::new(router(state.clone())).unwrap();
    let viewer=state.pg_insert(&principal,"user",json!({"email":format!("viewer-{tenant}@example.test"),"password":"password-test","role":"viewer"})).await.unwrap();
    let viewer_principal = Principal {
        user_id: Uuid::parse_str(viewer["id"].as_str().unwrap()).unwrap(),
        role: "viewer".into(),
        ..principal.clone()
    };
    let viewer_token = state
        .pg_insert(&viewer_principal, "token", json!({}))
        .await
        .unwrap();
    let authorization = format!("Bearer {}", viewer_token["token"].as_str().unwrap());
    server
        .post("/api/v1/hosts")
        .add_header("authorization", authorization.clone())
        .json(&json!({"name":"forbidden"}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .put(&format!("/api/v1/hosts/{host_id}"))
        .add_header("authorization", authorization.clone())
        .json(&json!({"name":"forbidden"}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .delete(&format!("/api/v1/hosts/{host_id}"))
        .add_header("authorization", authorization)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    assert!(
        state.pg_audits(&principal).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len()
            >= 10
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn api_postgres_reconciles_template_triggers_and_validates_host_names() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let db = crate::db::Db::connect(&url).await.unwrap();
    let tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
        .bind(tenant)
        .bind(format!("reconcile-test-{tenant}"))
        .execute(&db.pool)
        .await
        .unwrap();
    let principal = Principal {
        user_id: Uuid::new_v4(),
        tenant_id: tenant,
        email: format!("{tenant}@example.test"),
        role: "owner".into(),
        host_group_id: None,
    };
    let dir = std::env::temp_dir().join(format!("kestrel-api-reconcile-{tenant}"));
    let secrets =
        Arc::new(crate::secrets::SecretBox::load_or_create(&dir.join("secret.key")).unwrap());
    let state = ApiState::new(
        Arc::new(MemoryCatalog::new()),
        Arc::new(crate::MemoryStore::new()),
    )
    .with_database(db.clone(), secrets);
    let id = |value: &Value| Uuid::parse_str(value["id"].as_str().unwrap()).unwrap();
    // Names outside the PromQL label alphabet could never be scoped.
    for name in ["web 1", "web\"1", ""] {
        let err = state
            .pg_insert(&principal, "host", json!({ "name": name }))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST, "{name}");
    }
    let host = id(&state
        .pg_insert(&principal, "host", json!({"name":"switch-1.lan"}))
        .await
        .unwrap());
    let err = state
        .pg_update(&principal, "host", host, json!({"name":"switch 1"}))
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let template = id(&state
        .pg_insert(&principal, "template", json!({"name":"SNMP"}))
        .await
        .unwrap());
    let parent = id(&state
        .pg_insert(&principal, "template", json!({"name":"Base"}))
        .await
        .unwrap());
    let source = id(&state
        .pg_insert(
            &principal,
            "trigger",
            json!({"name":"down","expression":"snmp_up == 0","template_id":template}),
        )
        .await
        .unwrap());
    let copies = || async {
        sqlx::query_as::<_, (String, String, bool, Option<Uuid>)>(
            "SELECT name,expression,enabled,source_trigger_id FROM triggers WHERE tenant_id=$1 AND host_id=$2 ORDER BY name",
        )
        .bind(tenant)
        .bind(host)
        .fetch_all(&db.pool)
        .await
        .unwrap()
    };
    // An agentless host gets copies as soon as it is linked.
    state
        .pg_link_template(&principal, host, template)
        .await
        .unwrap();
    assert_eq!(
        copies().await,
        vec![("down".into(), "snmp_up == 0".into(), true, Some(source))]
    );
    // Renames and edits reach the copy through its source.
    state
        .pg_update(
            &principal,
            "trigger",
            source,
            json!({"name":"unreachable","expression":"snmp_up < 1"}),
        )
        .await
        .unwrap();
    assert_eq!(
        copies().await,
        vec![(
            "unreachable".into(),
            "snmp_up < 1".into(),
            true,
            Some(source)
        )]
    );
    // Inherited triggers materialise when the parent link or trigger appears.
    state
        .pg_link_parent(&principal, template, parent)
        .await
        .unwrap();
    let inherited = id(&state
        .pg_insert(
            &principal,
            "trigger",
            json!({"name":"base","expression":"up == 0","template_id":parent}),
        )
        .await
        .unwrap());
    assert_eq!(copies().await.len(), 2);
    assert!(copies()
        .await
        .contains(&("base".into(), "up == 0".into(), true, Some(inherited))));
    // Deleting a source disables its copy and keeps the row for history.
    state
        .pg_delete(&principal, "trigger", source)
        .await
        .unwrap();
    assert!(copies()
        .await
        .contains(&("unreachable".into(), "snmp_up < 1".into(), false, None)));
    // Detaching a trigger from its template retires its copies.
    state
        .pg_update(
            &principal,
            "trigger",
            inherited,
            json!({"template_id":null}),
        )
        .await
        .unwrap();
    assert!(copies()
        .await
        .contains(&("base".into(), "up == 0".into(), false, Some(inherited))));
    state
        .pg_update(&principal, "host", host, json!({"name":"switch-2.lan"}))
        .await
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn api_postgres_users_have_unique_emails_delete_cleanly_and_grants_revoke() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let db = crate::db::Db::connect(&url).await.unwrap();
    let parent = Uuid::new_v4();
    let other = Uuid::new_v4();
    for id in [parent, other] {
        sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
            .bind(id)
            .bind(format!("identity-test-{id}"))
            .execute(&db.pool)
            .await
            .unwrap();
    }
    let email = format!("owner-{parent}@example.test");
    let owner = db
        .insert_user(
            &crate::db::TenantId(parent),
            crate::db::NewUser {
                email: email.clone(),
                password_hash: crate::passwords::hash_password("password-test").unwrap(),
                role: "owner".into(),
                host_group_id: None,
            },
        )
        .await
        .unwrap();
    let principal = Principal {
        user_id: owner.id,
        tenant_id: parent,
        email: email.clone(),
        role: "owner".into(),
        host_group_id: None,
    };
    let other_principal = Principal {
        tenant_id: other,
        user_id: Uuid::new_v4(),
        ..principal.clone()
    };
    let dir = std::env::temp_dir().join(format!("kestrel-api-identity-{parent}"));
    let secrets =
        Arc::new(crate::secrets::SecretBox::load_or_create(&dir.join("secret.key")).unwrap());
    let state = ApiState::new(
        Arc::new(MemoryCatalog::new()),
        Arc::new(crate::MemoryStore::new()),
    )
    .with_database(db.clone(), secrets);

    // One tenant cannot hold the same address twice, in any letter case.
    let err = state
        .pg_insert(
            &principal,
            "user",
            json!({"email":email.to_uppercase(),"password":"password-test","role":"viewer"}),
        )
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    session_for(&state, &email.to_uppercase(), "password-test", None).await;

    // A user who has signed in (session and audit rows) can be deleted.
    let member_email = format!("member-{parent}@example.test");
    let member = state
        .pg_insert(
            &principal,
            "user",
            json!({"email":member_email,"password":"password-test","role":"admin"}),
        )
        .await
        .unwrap();
    let member_id = Uuid::parse_str(member["id"].as_str().unwrap()).unwrap();
    session_for(&state, &member_email, "password-test", None).await;
    let member_principal = Principal {
        user_id: member_id,
        role: "admin".into(),
        ..principal.clone()
    };
    state
        .pg_insert(&member_principal, "token", json!({"name":"member"}))
        .await
        .unwrap();
    state
        .pg_delete(&principal, "user", member_id)
        .await
        .unwrap();
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND user_id IS NULL")
            .bind(parent)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(audits >= 1, "audit history must survive user deletion");

    // Revoking a grant ends sessions that were switched into the child.
    let child = state
        .pg_create_tenant(
            &principal,
            json!({"name":format!("identity-child-{parent}")}),
        )
        .await
        .unwrap();
    let child_id = Uuid::parse_str(child["id"].as_str().unwrap()).unwrap();
    let grants = state.pg_grants(&principal).await.unwrap();
    assert!(grants["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant["user_id"] == json!(owner.id) && grant["tenant_id"] == json!(child_id)));
    assert!(state.pg_grants(&other_principal).await.unwrap()["items"]
        .as_array()
        .unwrap()
        .is_empty());
    let session = session_for(&state, &email, "password-test", None).await;
    state
        .pg_switch(&principal, &session, child_id)
        .await
        .unwrap();
    assert!(state
        .pg_principal(Some(&session), None)
        .await
        .unwrap()
        .is_some());
    let err = state
        .pg_revoke_grant(&other_principal, owner.id, child_id)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    state
        .pg_revoke_grant(&principal, owner.id, child_id)
        .await
        .unwrap();
    assert!(state
        .pg_principal(Some(&session), None)
        .await
        .unwrap()
        .is_none());
    let err = state
        .pg_revoke_grant(&principal, owner.id, child_id)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn api_postgres_login_selects_a_tenant_and_audits_failures() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let db = crate::db::Db::connect(&url).await.unwrap();
    let email = format!("{}@example.test", Uuid::new_v4());
    let mut tenants = Vec::new();
    for password in ["first-password", "second-password"] {
        let id = Uuid::new_v4();
        let name = format!("login-test-{id}");
        sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
            .bind(id)
            .bind(&name)
            .execute(&db.pool)
            .await
            .unwrap();
        let user = db
            .insert_user(
                &crate::db::TenantId(id),
                crate::db::NewUser {
                    email: email.clone(),
                    password_hash: crate::passwords::hash_password(password).unwrap(),
                    role: "viewer".into(),
                    host_group_id: None,
                },
            )
            .await
            .unwrap();
        tenants.push((id, name, user.id));
    }
    let dir = std::env::temp_dir().join(format!("kestrel-api-pg-login-{}", tenants[0].0));
    let secrets =
        Arc::new(crate::secrets::SecretBox::load_or_create(&dir.join("secret.key")).unwrap());
    let state = ApiState::new(
        Arc::new(MemoryCatalog::new()),
        Arc::new(crate::MemoryStore::new()),
    )
    .with_database(db.clone(), secrets);

    // Ambiguous without a tenant: a wrong password is a plain refusal, the
    // right one lists only the tenant it matched and issues no session.
    assert!(matches!(
        sign_in(&state, &email, "wrong-password", None).await,
        LoginOutcome::Refused
    ));
    let LoginOutcome::ChooseTenant(choices) =
        sign_in(&state, &email, "second-password", None).await
    else {
        panic!("expected a tenant choice");
    };
    assert_eq!(
        choices,
        vec![json!({"id": tenants[1].0, "name": tenants[1].1})]
    );

    // Each tenant signs in by name or id with its own password only.
    let first = session_for(&state, &email, "first-password", Some(&tenants[0].1)).await;
    let principal = state
        .pg_principal(Some(&first), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (principal.tenant_id, principal.user_id),
        (tenants[0].0, tenants[0].2)
    );
    let second = session_for(
        &state,
        &email,
        "second-password",
        Some(&tenants[1].0.to_string()),
    )
    .await;
    let principal = state
        .pg_principal(Some(&second), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(principal.tenant_id, tenants[1].0);
    assert!(matches!(
        sign_in(&state, &email, "second-password", Some(&tenants[0].1)).await,
        LoginOutcome::Refused
    ));
    assert!(matches!(
        sign_in(&state, &email, "first-password", Some("no-such-tenant")).await,
        LoginOutcome::Refused
    ));
    assert!(matches!(
        sign_in(&state, "nobody@example.test", "x", Some(&tenants[0].1)).await,
        LoginOutcome::Refused
    ));

    let failures: Vec<(Option<Uuid>, String, Value)> = sqlx::query_as(
        "SELECT user_id,target,detail FROM audit_log WHERE tenant_id=$1 AND action='session.login_failed' ORDER BY created_at,id",
    )
    .bind(tenants[0].0)
    .fetch_all(&db.pool)
    .await
    .unwrap();
    // The ambiguous wrong password, the wrong tenant's password and the
    // unknown email under this tenant.
    assert_eq!(failures.len(), 3, "{failures:?}");
    assert_eq!(failures[0].0, Some(tenants[0].2));
    assert_eq!(failures[0].1, email);
    assert_eq!(failures[0].2["source"], json!("192.0.2.10"));
    assert_eq!(failures[2].0, None);
    assert_eq!(failures[2].1, "nobody@example.test");
    for (_, _, detail) in &failures {
        assert!(!detail.to_string().contains("password"));
    }
    let logins: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='session.login'",
    )
    .bind(tenants[0].0)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(logins, 1);

    // A single-tenant email is unchanged.
    let solo_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)")
        .bind(solo_tenant)
        .bind(format!("login-test-{solo_tenant}"))
        .execute(&db.pool)
        .await
        .unwrap();
    let solo = format!("{solo_tenant}@example.test");
    db.insert_user(
        &crate::db::TenantId(solo_tenant),
        crate::db::NewUser {
            email: solo.clone(),
            password_hash: crate::passwords::hash_password("solo-password").unwrap(),
            role: "viewer".into(),
            host_group_id: None,
        },
    )
    .await
    .unwrap();
    session_for(&state, &solo, "solo-password", None).await;
}
