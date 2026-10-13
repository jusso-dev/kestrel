//! Kestrel server library. The binary in `main.rs` calls [`run`].

pub mod admin;
pub mod ca;
pub mod config;
mod http;
mod perms;
mod store;
mod tls;

pub use http::{start, RunningServer};

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
        victoria = %cfg.victoria_url,
        public = %cfg.public_url,
        smtp = cfg.smtp.is_some(),
        "configuration loaded"
    );
    println!("kestrel-server {}", env!("CARGO_PKG_VERSION"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let server = start(cfg).await?;
        tokio::signal::ctrl_c().await?;
        server.shutdown();
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
