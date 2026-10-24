//! Enrolment, renewal, and authenticated ingest.

use crate::api::ApiState;
use crate::ca::{self, Ca};
use crate::config::ServerConfigFile;
use crate::config_compile::{builtin_templates, compile_agent_config, HostView};
use crate::ingest::{self, IngestDecision, IngestQueue};
use crate::perms;
use crate::quota::Quotas;
use crate::store::{Directory, EnrolCommit, MemoryStore, MetricStore, VictoriaStore};
use crate::tls::{self, PeerAcceptor, PeerCert};
use crate::ServerError;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<Directory>,
    ca: Arc<Mutex<Ca>>,
    ca_pem: Arc<String>,
    ingest: Arc<IngestQueue>,
    quotas: Arc<Quotas>,
    db: Option<crate::db::Db>,
    metrics: Arc<dyn MetricStore>,
    ingest_permits: Arc<tokio::sync::Semaphore>,
    security_limits: Arc<Quotas>,
}

#[derive(Clone, Copy, Debug)]
struct AuthedAgent(Uuid);

#[derive(Debug, Deserialize)]
struct EnrolRequest {
    token: String,
    csr_pem: String,
    hostname: String,
    os: String,
    arch: String,
}

#[derive(Debug, Serialize)]
struct EnrolResponse {
    agent_id: Uuid,
    cert_pem: String,
    ca_pem: String,
}

#[derive(Debug, Deserialize)]
struct RenewRequest {
    csr_pem: String,
}

#[derive(Debug, Serialize)]
struct RenewResponse {
    cert_pem: String,
    ca_pem: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

/// HTTPS listeners for enrolment and ingest.
pub struct RunningServer {
    pub addr: SocketAddr,
    pub ingest_addr: Option<SocketAddr>,
    handles: Vec<axum_server::Handle>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningServer {
    pub fn shutdown(&self) {
        for handle in &self.handles {
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown();
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Create the CA and server certificate when needed, then serve until dropped.
pub async fn start(cfg: ServerConfigFile) -> Result<RunningServer, ServerError> {
    start_with(cfg, None).await
}

/// Serve HTTPS. A database selects VictoriaMetrics; tests without one use the
/// in-memory store so enrolment does not wait on a metrics process.
pub async fn start_with(
    cfg: ServerConfigFile,
    mut db: Option<crate::db::Db>,
) -> Result<RunningServer, ServerError> {
    if let Some(db) = db.as_mut() {
        db.log_retention_days = i32::try_from(cfg.log_retention_days)
            .map_err(|_| ServerError::new("log retention is too large"))?;
    }
    let ca = Ca::load_or_create(&cfg.ca.cert_path, &cfg.ca.key_path)?;
    let ca_pem = ca.cert_pem().to_string();
    let (dns, ips) = ca::server_names(&cfg.public_url, cfg.listen.ip());
    let (server_cert, server_key) = if cfg.tls.cert_path.is_file() && cfg.tls.key_path.is_file() {
        perms::restrict_private_key(&cfg.tls.key_path)?;
        (
            std::fs::read_to_string(&cfg.tls.cert_path)?,
            std::fs::read_to_string(&cfg.tls.key_path)?,
        )
    } else if cfg.tls.cert_path.exists() || cfg.tls.key_path.exists() {
        return Err(ServerError::new(
            "server certificate and key must both exist or both be absent",
        ));
    } else {
        let issued = ca.issue_server(&dns, &ips)?;
        perms::write_certificate(&cfg.tls.cert_path, &issued.cert_pem)?;
        perms::write_private_key(&cfg.tls.key_path, &issued.key_pem)?;
        (issued.cert_pem, issued.key_pem)
    };
    let store = Arc::new(Directory::open(&cfg.data_dir)?);
    let metrics: Arc<dyn MetricStore> = if db.is_some() {
        Arc::new(VictoriaStore::new(cfg.victoria_url.as_str())?)
    } else {
        Arc::new(MemoryStore::new())
    };
    let (queue, rx) = IngestQueue::new(ingest::INGEST_QUEUE_CAPACITY);
    let ingest = Arc::new(queue);
    let writer = tokio::spawn(ingest::run_writer(rx, Arc::clone(&metrics), 1_000));
    let quotas = Arc::new(Quotas::per_second(50_000));
    let mut api_state = ApiState::new(
        Arc::new(crate::api::MemoryCatalog::new()),
        Arc::clone(&metrics),
    );
    api_state.secure_cookie = true;
    api_state.directory = Some(Arc::clone(&store));
    api_state.smtp = cfg.smtp.clone();
    api_state.otlp_drop = cfg.otlp_drop_attributes.clone();
    api_state.egress = Arc::new(egress_guard(&cfg));
    api_state.quotas = Arc::clone(&quotas);
    api_state.db = db.clone();
    api_state.secrets = Some(Arc::new(crate::secrets::SecretBox::load_or_create(
        &cfg.data_dir.join("secret.key"),
    )?));
    let state = AppState {
        store,
        ca: Arc::new(Mutex::new(ca)),
        ca_pem: Arc::new(ca_pem.clone()),
        ingest,
        quotas,
        db,
        metrics,
        ingest_permits: Arc::new(tokio::sync::Semaphore::new(16)),
        security_limits: Arc::new(Quotas::per_second(1)),
    };
    let mut workers = crate::runtime::spawn(api_state.clone(), cfg.public_url.to_string());
    if api_state.db.is_some() {
        workers.push(crate::security::spawn(api_state.clone()));
    }
    let app = router(state, api_state);
    let public_tls = tls::rustls_config(&server_cert, &server_key, &ca_pem, false)?;
    let (handle, task, addr) = spawn_listener(cfg.listen, public_tls, app.clone()).await?;
    let mut handles = vec![handle];
    let mut tasks = vec![task];
    let mut ingest_addr = None;
    if let Some(listen) = cfg.ingest_listen {
        let ingest_tls = tls::rustls_config(&server_cert, &server_key, &ca_pem, true)?;
        let (handle, task, bound) = spawn_listener(listen, ingest_tls, app).await?;
        ingest_addr = Some(bound);
        handles.push(handle);
        tasks.push(task);
    }
    tasks.push(writer);
    tasks.extend(workers);
    tracing::info!(%addr, ?ingest_addr, "https listeners started");
    Ok(RunningServer {
        addr,
        ingest_addr,
        handles,
        tasks,
    })
}

fn router(state: AppState, api_state: ApiState) -> Router {
    let ingest_routes = Router::new()
        .route("/api/v1/ingest", post(ingest))
        .layer(DefaultBodyLimit::max(ingest::INGEST_BODY_LIMIT))
        .route_layer(middleware::from_fn_with_state(state.clone(), bound_ingest));
    let guarded = Router::new()
        .merge(ingest_routes)
        .route("/api/v1/renew", post(renew))
        .route("/api/v1/agent/config", get(agent_config))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_agent));
    Router::new()
        .route("/api/v1/enrol", post(enrol))
        .merge(guarded)
        .with_state(state)
        .merge(crate::api::router(api_state))
        .merge(crate::web::router())
}

async fn bound_ingest(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Ok(_permit) = state.ingest_permits.try_acquire() else {
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    next.run(request).await
}

/// Refuse tenant-supplied URLs that reach the shared metric store or this
/// server's own bound listeners.
fn egress_guard(cfg: &ServerConfigFile) -> kestrel_checks::EgressGuard {
    let mut guard = kestrel_checks::EgressGuard::new(cfg.allow_loopback_targets);
    if let (Some(host), Some(port)) = (
        cfg.victoria_url.host_str(),
        cfg.victoria_url.port_or_known_default(),
    ) {
        guard = guard.deny_endpoint(host, port);
    }
    for addr in [Some(cfg.listen), cfg.ingest_listen].into_iter().flatten() {
        if !addr.ip().is_unspecified() {
            guard = guard.deny_endpoint(&addr.ip().to_string(), addr.port());
        }
    }
    guard
}

async fn spawn_listener(
    addr: SocketAddr,
    config: axum_server::tls_rustls::RustlsConfig,
    app: Router,
) -> Result<(axum_server::Handle, tokio::task::JoinHandle<()>, SocketAddr), ServerError> {
    let handle = axum_server::Handle::new();
    let acceptor = PeerAcceptor::new(axum_server::tls_rustls::RustlsAcceptor::new(config));
    let bound_handle = handle.clone();
    let task = tokio::spawn(async move {
        let result = axum_server::bind(addr)
            .acceptor(acceptor)
            .handle(bound_handle)
            .serve(app.into_make_service())
            .await;
        if let Err(err) = result {
            tracing::error!(error = %err, "https listener ended");
        }
    });
    let bound = handle.listening().await.ok_or_else(|| {
        ServerError::new(format!("https listener on {addr} stopped before it bound"))
    })?;
    Ok((handle, task, bound))
}

async fn enrol(
    State(state): State<AppState>,
    Json(body): Json<EnrolRequest>,
) -> Result<Json<EnrolResponse>, ApiError> {
    if body.token.is_empty() || body.csr_pem.is_empty() || body.hostname.is_empty() {
        return Err(reject(
            axum::http::StatusCode::BAD_REQUEST,
            "token, csr_pem, and hostname are required",
        ));
    }
    let (tenant_id, group) = match state.store.token_scope(&body.token) {
        Ok(scope) => scope,
        Err(err) => {
            tracing::info!(error = %err, "enrolment rejected");
            return Err(token_response(err));
        }
    };
    if let Some(db) = &state.db {
        if let Err(err) = db
            .check_enrolment_host(tenant_id, &body.hostname, group.as_deref())
            .await
        {
            tracing::info!(error = %err, "enrolment rejected");
            let message = err.to_string();
            return Err(if message.starts_with(crate::db::HOST_CONFLICT) {
                reject(axum::http::StatusCode::CONFLICT, message)
            } else if message == "unknown enrolment host group" {
                reject(axum::http::StatusCode::BAD_REQUEST, message)
            } else {
                reject(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "enrolment store failed",
                )
            });
        }
    }
    let agent_id = Uuid::new_v4();
    let issued = sign_agent(&state, &body.csr_pem, agent_id).await?;
    let not_after = issued.not_after_rfc3339.clone();
    let serial = issued.serial_hex.clone();
    if let Err(err) = state.store.commit_enrol(EnrolCommit {
        token: body.token,
        agent_id,
        hostname: body.hostname.clone(),
        os: body.os,
        arch: body.arch,
        cert_serial: serial,
        cert_not_after: not_after,
    }) {
        tracing::info!(error = %err, "enrolment rejected");
        return Err(token_response(err));
    }
    tracing::info!(%agent_id, hostname = %body.hostname, "agent enrolled");
    Ok(Json(EnrolResponse {
        agent_id,
        cert_pem: issued.pem,
        ca_pem: (*state.ca_pem).clone(),
    }))
}

async fn renew(
    State(state): State<AppState>,
    axum::Extension(agent): axum::Extension<AuthedAgent>,
    Json(body): Json<RenewRequest>,
) -> Result<Json<RenewResponse>, ApiError> {
    if body.csr_pem.is_empty() {
        return Err(reject(
            axum::http::StatusCode::BAD_REQUEST,
            "csr_pem is required",
        ));
    }
    let issued = sign_agent(&state, &body.csr_pem, agent.0).await?;
    if let Err(err) =
        state
            .store
            .commit_renew(agent.0, &issued.serial_hex, &issued.not_after_rfc3339)
    {
        tracing::info!(error = %err, agent_id = %agent.0, "renewal rejected");
        return Err(reject(
            axum::http::StatusCode::UNAUTHORIZED,
            "client certificate rejected",
        ));
    }
    tracing::info!(agent_id = %agent.0, "agent certificate renewed");
    Ok(Json(RenewResponse {
        cert_pem: issued.pem,
        ca_pem: (*state.ca_pem).clone(),
    }))
}

async fn ingest(
    State(state): State<AppState>,
    axum::Extension(agent): axum::Extension<AuthedAgent>,
    body: Bytes,
) -> axum::http::StatusCode {
    if body.len() > ingest::INGEST_BODY_LIMIT {
        return axum::http::StatusCode::PAYLOAD_TOO_LARGE;
    }
    let (tenant_id, host) = state
        .store
        .agent_meta(agent.0)
        .unwrap_or((crate::store::DEFAULT_TENANT_ID, "unknown".to_string()));
    let prepared =
        match ingest::prepare_batch(&body, &tenant_id.to_string(), &host, &agent.0.to_string()) {
            Ok(prepared) => prepared,
            Err(IngestDecision::Rejected(_)) => return axum::http::StatusCode::BAD_REQUEST,
            Err(_) => return axum::http::StatusCode::BAD_REQUEST,
        };
    let samples = u32::try_from(prepared.samples.len()).unwrap_or(u32::MAX);
    if let Some(db) = &state.db {
        let Some(details) = state.store.agent_details(agent.0) else {
            return axum::http::StatusCode::UNAUTHORIZED;
        };
        let host = match db.ensure_enrolled_agent(&details).await {
            Ok(host) => host,
            Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE,
        };
        let last: Result<(i64,i32), _> =
            sqlx::query_as("SELECT a.last_seq,t.samples_per_second FROM agents a JOIN tenants t ON t.id=a.tenant_id WHERE a.tenant_id=$1 AND a.id=$2")
                .bind(tenant_id)
                .bind(agent.0)
                .fetch_one(&db.pool)
                .await;
        let Ok((last, rate)) = last else {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE;
        };
        if prepared.seq <= last as u64 {
            return axum::http::StatusCode::OK;
        }
        if state
            .quotas
            .check_with_rate(tenant_id, samples.max(1), u32::try_from(rate).unwrap_or(0))
            .is_err()
        {
            return axum::http::StatusCode::TOO_MANY_REQUESTS;
        }
        return match db
            .ingest_prepared(tenant_id, host, agent.0, prepared, state.metrics.as_ref())
            .await
        {
            Ok(_) => axum::http::StatusCode::OK,
            Err(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        };
    }
    if state.quotas.check(tenant_id, samples).is_err() {
        return axum::http::StatusCode::TOO_MANY_REQUESTS;
    }
    match state
        .ingest
        .submit(&agent.0.to_string(), prepared.seq, prepared.samples)
    {
        IngestDecision::Accepted | IngestDecision::Duplicate => axum::http::StatusCode::OK,
        IngestDecision::Overloaded => axum::http::StatusCode::TOO_MANY_REQUESTS,
        IngestDecision::Rejected(_) => axum::http::StatusCode::BAD_REQUEST,
    }
}

async fn agent_config(
    State(state): State<AppState>,
    axum::Extension(agent): axum::Extension<AuthedAgent>,
    request: Request,
) -> Response {
    let host_name = state
        .store
        .agent_meta(agent.0)
        .map(|(_, host)| host)
        .unwrap_or_else(|| "unknown".to_string());
    let templates = builtin_templates();
    let linux = templates.into_iter().find(|doc| doc.name == "Linux");
    let templates = linux.into_iter().collect::<Vec<_>>();
    let (config, etag) = if let Some(db) = &state.db {
        let Some(details) = state.store.agent_details(agent.0) else {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        };
        let host = match db.ensure_enrolled_agent(&details).await {
            Ok(host) => host,
            Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        match db
            .linked_agent_config(details.tenant_id, host, host_name)
            .await
        {
            Ok(config) => config,
            Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        compile_agent_config(
            &HostView {
                name: host_name,
                overrides: BTreeMap::new(),
            },
            &templates,
        )
    };
    let presented = request
        .headers()
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if presented == etag {
        return axum::http::StatusCode::NOT_MODIFIED.into_response();
    }
    let checks = config
        .checks
        .iter()
        .map(|check| {
            serde_json::json!({
                "id": check.id,
                "command": check.command,
                "interval_s": check.interval_s,
                "timeout_s": check.timeout_s,
            })
        })
        .collect::<Vec<_>>();
    let logs = config
        .logs
        .iter()
        .map(|log| serde_json::json!({ "path": log.path, "pattern": log.pattern }))
        .collect::<Vec<_>>();
    let body = serde_json::json!({
        "interval_s": config.interval_s,
        "checks": checks,
        "logs": logs,
        "items": config.items.iter().map(|item| serde_json::json!({
            "key": item.key,
            "kind": item.kind,
            "interval_s": item.interval_s,
            "params_json": item.params_json,
        })).collect::<Vec<_>>(),
        "etag": etag,
    });
    ([(axum::http::header::ETAG, etag)], Json(body)).into_response()
}

async fn require_agent(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let der = request
        .extensions()
        .get::<PeerCert>()
        .map(|peer| peer.der.clone());
    let Some(der) = der else {
        return reject(
            axum::http::StatusCode::UNAUTHORIZED,
            "client certificate required",
        )
        .into_response();
    };
    let presented = match ca::presented_identity(&der) {
        Ok(presented) => presented,
        Err(err) => {
            tracing::info!(error = %err, "client certificate rejected");
            return reject(
                axum::http::StatusCode::UNAUTHORIZED,
                "client certificate rejected",
            )
            .into_response();
        }
    };
    if !state
        .store
        .authorize(presented.agent_id, &presented.serial_hex)
    {
        if let Some(tenant) = state.store.security_meta(presented.agent_id) {
            if state.security_limits.check(tenant, 1).is_ok() {
                let _ = state.store.record_security_rejection(presented.agent_id);
            }
        }
        return reject(
            axum::http::StatusCode::UNAUTHORIZED,
            "client certificate rejected",
        )
        .into_response();
    }
    request
        .extensions_mut()
        .insert(AuthedAgent(presented.agent_id));
    next.run(request).await
}

async fn sign_agent(
    state: &AppState,
    csr_pem: &str,
    agent_id: Uuid,
) -> Result<ca::IssuedCert, ApiError> {
    let ca = Arc::clone(&state.ca);
    let csr_pem = csr_pem.to_string();
    match tokio::task::spawn_blocking(move || {
        let guard = ca.lock().unwrap_or_else(|err| err.into_inner());
        guard.sign_agent(&csr_pem, agent_id)
    })
    .await
    {
        Ok(Ok(issued)) => Ok(issued),
        Ok(Err(err)) => {
            tracing::info!(error = %err, "could not sign agent certificate");
            Err(reject(
                axum::http::StatusCode::BAD_REQUEST,
                "could not sign the certificate",
            ))
        }
        Err(err) => Err(reject(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            err.to_string(),
        )),
    }
}

struct ApiError {
    status: axum::http::StatusCode,
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.error })).into_response()
    }
}

fn reject(status: axum::http::StatusCode, error: impl Into<String>) -> ApiError {
    ApiError {
        status,
        error: error.into(),
    }
}

fn token_response(err: ServerError) -> ApiError {
    if err.to_string() == "enrolment token rejected" {
        reject(
            axum::http::StatusCode::UNAUTHORIZED,
            "enrolment token rejected",
        )
    } else {
        tracing::warn!(error = %err, "enrolment store failed");
        reject(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "enrolment store failed",
        )
    }
}
