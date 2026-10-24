//! Kestrel agent library. The binary in `main.rs` calls [`run`].

pub mod bootstrap;
pub mod buffer;
pub mod config;
pub mod desired;
pub mod identity;
pub mod inventory;
mod perms;
mod runtime;
pub mod scheduler;
pub mod service;
pub mod shipper;

use buffer::Buffer;
use scheduler::run_batcher;
use shipper::{sample_jitter, Shipper};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Load configuration and collect until the process is interrupted.
///
/// Samples are written to a size-capped segment log under the data directory
/// and posted to the configured server in order.
pub fn run() -> Result<(), AgentError> {
    run_with_shutdown(None)
}

pub(crate) fn run_with_shutdown(stop: Option<watch::Receiver<bool>>) -> Result<(), AgentError> {
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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(cfg, stop))
}

async fn serve(
    cfg: config::AgentConfigFile,
    mut stop: Option<watch::Receiver<bool>>,
) -> Result<(), AgentError> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let identity = tokio::select! {
        identity = identity::ensure(&cfg) => identity?,
        _ = requested_stop(&mut stop) => return Ok(()),
    };
    let agent_id = if let Some(id) = &identity {
        id.agent_id.clone()
    } else {
        load_or_create_agent_id(&cfg.data_dir)?
    };
    let max_bytes = cfg.buffer_max_mb.saturating_mul(1024).saturating_mul(1024);
    let buffer = Arc::new(Mutex::new(Buffer::open(
        cfg.data_dir.join("buffer"),
        max_bytes,
    )?));
    let (sample_tx, sample_rx) = mpsc::channel(256);
    let (collect_tx, collect_rx) = mpsc::channel(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let latest = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let forwarder = tokio::spawn(runtime::forward_samples(
        collect_rx,
        sample_tx,
        latest.clone(),
    ));

    let batch_buffer = Arc::clone(&buffer);
    let batch_id = agent_id.clone();
    let batch_shutdown = shutdown_rx.clone();
    let batcher = tokio::spawn(async move {
        run_batcher(sample_rx, batch_buffer, batch_id, batch_shutdown).await;
    });

    let ship_buffer = Arc::clone(&buffer);
    let ship_shutdown = shutdown_rx.clone();
    let shipper = match &identity {
        Some(id) => Shipper::with_identity(&cfg.server_url, &id.client_identity())?,
        None => Shipper::new(&cfg.server_url)?,
    };
    let shipper = Arc::new(shipper);
    let config_task = tokio::spawn(runtime::poll_config(
        cfg.clone(),
        shipper.clone(),
        collect_tx,
        buffer.clone(),
        agent_id.clone(),
        shutdown_rx.clone(),
    ));
    let inventory_task = tokio::spawn(inventory::run(
        buffer.clone(),
        agent_id,
        shutdown_rx.clone(),
    ));
    let metrics_task = cfg.prometheus_listen.clone().map(|addr| {
        let stop = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(err) = runtime::serve_metrics(&addr, latest, stop).await {
                tracing::error!(error=%err,"Prometheus listener failed");
            }
        })
    });
    let shipper_task_client = Arc::clone(&shipper);
    let shipper_task = tokio::spawn(async move {
        shipper_task_client
            .run(
                ship_buffer,
                ship_shutdown,
                tokio::time::sleep,
                sample_jitter,
            )
            .await;
    });
    let renew_task = identity.as_ref().map(|_| {
        let renew_dir = cfg.data_dir.clone();
        let renew_url = cfg.server_url.clone();
        let renew_shipper = Arc::clone(&shipper);
        let mut renew_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = renew_shutdown.changed() => break,
                    _ = ticker.tick() => match identity::refresh(&renew_dir, &renew_url).await {
                        Ok(Some(updated)) => match shipper::mtls_client(&updated.client_identity()) {
                            Ok(client) => renew_shipper.replace_client(client),
                            Err(err) => {
                                tracing::warn!(error = %err, "renewed certificate could not be loaded");
                            }
                        },
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(error = %err, "certificate renewal check failed");
                        }
                    },
                }
            }
        })
    });

    let sync_buffer = Arc::clone(&buffer);
    let mut sync_shutdown = shutdown_rx;
    let syncer = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = sync_shutdown.changed() => break,
                _ = ticker.tick() => {
                    let mut guard = sync_buffer.lock().unwrap_or_else(|err| err.into_inner());
                    if let Err(err) = guard.poll_sync() {
                        tracing::warn!(error = %err, "buffer sync failed");
                    }
                }
            }
        }
    });

    tokio::select! {
        result = shutdown_signal() => result?,
        _ = requested_stop(&mut stop) => {},
    }
    let _ = shutdown_tx.send(true);
    let _ = config_task.await;
    let _ = inventory_task.await;
    let _ = forwarder.await;
    if let Some(task) = metrics_task {
        let _ = task.await;
    }
    let _ = batcher.await;
    let _ = shipper_task.await;
    if let Some(task) = renew_task {
        let _ = task.await;
    }
    let _ = syncer.await;
    let mut guard = buffer.lock().unwrap_or_else(|err| err.into_inner());
    guard.sync()?;
    Ok(())
}

/// Wait for Ctrl-C, or SIGTERM on Unix (sent by systemd and launchd on stop).
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

async fn requested_stop(stop: &mut Option<watch::Receiver<bool>>) {
    if let Some(stop) = stop {
        if !*stop.borrow() {
            let _ = stop.changed().await;
        }
    } else {
        std::future::pending::<()>().await;
    }
}

fn load_or_create_agent_id(data_dir: &Path) -> Result<String, AgentError> {
    let path = data_dir.join("agent_id");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let id = text.trim();
        if !id.is_empty() {
            return Ok(id.to_string());
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    let tmp = data_dir.join("agent_id.tmp");
    std::fs::write(&tmp, &id)?;
    replace_file(&tmp, &path)?;
    Ok(id)
}

fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(err) => {
            if to.exists() {
                std::fs::remove_file(to)?;
                std::fs::rename(from, to)
            } else {
                Err(err)
            }
        }
    }
}

/// A failure while loading configuration or running the agent.
#[derive(Debug)]
pub struct AgentError {
    message: String,
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentError {}

impl From<config::ConfigError> for AgentError {
    fn from(err: config::ConfigError) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for AgentError {
    fn from(err: std::io::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<shipper::ShipError> for AgentError {
    fn from(err: shipper::ShipError) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<identity::IdentityError> for AgentError {
    fn from(err: identity::IdentityError) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_is_stable_across_restarts() {
        let dir = std::env::temp_dir().join(format!("kestrel-agent-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_or_create_agent_id(&dir).unwrap();
        let second = load_or_create_agent_id(&dir).unwrap();
        assert_eq!(first, second);
        assert!(!first.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
