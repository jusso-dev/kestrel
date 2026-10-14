//! Two tenants must not see each other's hosts or metrics.

use kestrel_server::api::{router, ApiState, MemoryCatalog};
use kestrel_server::{LabelledSample, MemoryStore, MetricStore};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn isolation_lists_gets_and_metrics_stay_inside_the_tenant() {
    let tenant_a = Uuid::from_u128(101);
    let tenant_b = Uuid::from_u128(202);
    let catalog = Arc::new(MemoryCatalog::new());
    catalog.add_tenant(tenant_a, "a", None);
    catalog.add_tenant(tenant_b, "b", None);
    catalog
        .add_user(tenant_a, "a@example.com", "correct-horse", "owner", None)
        .unwrap();
    catalog
        .add_user(tenant_b, "b@example.com", "correct-horse", "owner", None)
        .unwrap();
    let store = Arc::new(MemoryStore::new());
    let state = ApiState::new(Arc::clone(&catalog), store.clone());
    let mut server = axum_test::TestServer::builder()
        .save_cookies()
        .build(router(state))
        .unwrap();
    server.save_cookies();

    server
        .post("/api/v1/login")
        .json(&json!({ "email": "a@example.com", "password": "correct-horse" }))
        .await
        .assert_status_ok();
    let host_a = server
        .post("/api/v1/hosts")
        .json(&json!({ "name": "visible-a" }))
        .await
        .json::<Value>();
    server
        .post("/api/v1/logout")
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    server
        .post("/api/v1/login")
        .json(&json!({ "email": "b@example.com", "password": "correct-horse" }))
        .await
        .assert_status_ok();
    let host_b = server
        .post("/api/v1/hosts")
        .json(&json!({ "name": "secret-b" }))
        .await
        .json::<Value>();
    let listed = server.get("/api/v1/hosts").await.text();
    assert!(listed.contains("secret-b"), "{listed}");
    assert!(!listed.contains("visible-a"), "{listed}");
    let missing = server
        .get(&format!("/api/v1/hosts/{}", host_a["id"].as_str().unwrap()))
        .await;
    assert_eq!(missing.status_code(), axum::http::StatusCode::NOT_FOUND);

    store
        .write(vec![
            LabelledSample {
                name: "up".to_string(),
                labels: vec![
                    ("tenant".to_string(), tenant_a.to_string()),
                    ("host".to_string(), "visible-a".to_string()),
                ],
                value: 1.0,
                timestamp_ms: 1_700_000_000_000,
            },
            LabelledSample {
                name: "up".to_string(),
                labels: vec![
                    ("tenant".to_string(), tenant_b.to_string()),
                    ("host".to_string(), "secret-b".to_string()),
                ],
                value: 1.0,
                timestamp_ms: 1_700_000_000_000,
            },
        ])
        .await
        .unwrap();
    let metrics = server
        .get("/api/v1/metrics/query")
        .add_query_param("query", "up")
        .add_query_param("time", "1700000000")
        .await
        .text();
    assert!(metrics.contains("secret-b"), "{metrics}");
    assert!(!metrics.contains("visible-a"), "{metrics}");
    assert!(!metrics.contains(&tenant_a.to_string()), "{metrics}");
    let switched = server
        .post("/api/v1/session/tenant")
        .json(&json!({ "tenant_id": tenant_a }))
        .await;
    assert_eq!(switched.status_code(), axum::http::StatusCode::FORBIDDEN);
    let _ = host_b;
}
