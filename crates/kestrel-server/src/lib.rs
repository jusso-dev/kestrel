//! Kestrel server library. The binary in `main.rs` calls [`run`].

pub mod config;

/// Load configuration and log the bind address.
///
/// The HTTP server is added with the ingest and API issues. This entry point
/// checks that the server configuration loads.
pub fn run() -> Result<(), config::ConfigError> {
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
    Ok(())
}
