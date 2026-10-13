//! Enrolment, renewal, and authenticated ingest.

use crate::ca::{self, Ca};
use crate::config::ServerConfigFile;
use crate::perms;
use crate::store::{Directory, EnrolCommit};
use crate::tls::{self, PeerAcceptor, PeerCert};
use crate::ServerError;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<Directory>,
    ca: Arc<Mutex<Ca>>,
    ca_pem: Arc<String>,
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
    let state = AppState {
        store,
        ca: Arc::new(Mutex::new(ca)),
        ca_pem: Arc::new(ca_pem.clone()),
    };
    let app = router(state);
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
    tracing::info!(%addr, ?ingest_addr, "https listeners started");
    Ok(RunningServer {
        addr,
        ingest_addr,
        handles,
        tasks,
    })
}

fn router(state: AppState) -> Router {
    let guarded = Router::new()
        .route("/api/v1/ingest", post(ingest))
        .route("/api/v1/renew", post(renew))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_agent));
    Router::new()
        .route("/api/v1/enrol", post(enrol))
        .merge(guarded)
        .with_state(state)
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
    if let Err(err) = state.store.check_token(&body.token) {
        tracing::info!(error = %err, "enrolment rejected");
        return Err(token_response(err));
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

async fn ingest() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
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
