//! Kestrel agent library. The binary in `main.rs` calls [`run`].

pub mod config;

/// Load configuration, log the result, and return.
///
/// The collector runtime is added with the scheduler. This entry point only
/// owns configuration so `kestrel-agent --config` can be checked on its own.
pub fn run() -> Result<(), config::ConfigError> {
    config::init_tracing();
    let path = config::config_path_from_args(std::env::args().skip(1));
    let cfg = config::load_agent_config(&path)?;
    tracing::info!(
        path = %path.display(),
        server = %cfg.server_url,
        data_dir = %cfg.data_dir.display(),
        interval_s = cfg.interval_s,
        allow_remote_commands = cfg.allow_remote_commands,
        "configuration loaded"
    );
    println!("kestrel-agent {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
