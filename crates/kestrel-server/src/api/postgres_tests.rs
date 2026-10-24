use super::*;

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
    assert!(state.pg_login(&email, "wrong-password").await.is_err());
    let session = state.pg_login(&email, "password-test").await.unwrap();
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
