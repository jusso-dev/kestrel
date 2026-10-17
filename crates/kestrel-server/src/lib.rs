//! Kestrel server library. The binary in `main.rs` calls [`run`].

pub mod admin;
pub mod api;
pub mod authz;
pub mod ca;
pub mod config;
pub mod config_compile;
pub mod db;
pub mod discovery;
pub mod escalation;
pub mod forward;
mod http;
pub mod ingest;
pub mod maintenance;
pub mod notify;
pub mod otlp;
pub mod passwords;
mod perms;
pub mod poller;
pub mod promql;
pub mod quota;
pub mod rules;
mod runtime;
pub mod secrets;
mod security;
mod store;
mod tls;
pub mod web;

pub use http::{start, start_with, RunningServer};
pub use store::{LabelledSample, MemoryStore, MetricStore};

use std::error::Error;

/// Load configuration, ensure the internal CA exists, and serve HTTPS.
pub fn run() -> Result<(), ServerError> {
    config::init_tracing();
    let path = config::config_path_from_args(std::env::args().skip(1));
    let cfg = config::load_server_config(&path)?;
    tracing::info!(
        path = %path.display(),
        listen = %cfg.listen,
        ingest = ?cfg.ingest_listen,
        victoria = %cfg.victoria_url.origin().ascii_serialization(),
        public = %cfg.public_url.origin().ascii_serialization(),
        smtp = cfg.smtp.is_some(),
        "configuration loaded"
    );
    println!("kestrel-server {}", env!("CARGO_PKG_VERSION"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let db = db::Db::connect(&cfg.database_url).await?;
        tracing::info!("database migrations applied");
        let _ = poller::TimeoutPool::new(poller::DEFAULT_PERMITS);
        let _ = poller::snmp_templates().len();
        if let Err(err) = config_compile::ensure_builtin_templates(&db).await {
            tracing::warn!(error = %err, "built-in templates were not loaded");
        }
        let server = start_with(cfg, Some(db.clone())).await?;
        tokio::signal::ctrl_c().await?;
        server.shutdown();
        drop(db);
        Ok(())
    })
}

/// A failure while loading configuration or serving HTTPS.
#[derive(Debug)]
pub struct ServerError {
    message: String,
}

impl ServerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ServerError {}

impl From<config::ConfigError> for ServerError {
    fn from(err: config::ConfigError) -> Self {
        Self::new(err.to_string())
    }
}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}

#[cfg(test)]
mod enrol_tests;
