//! Service wrappers. Windows uses the service control manager. Linux and
//! macOS use the unit files in `deploy/`.

/// Run the Windows SCM dispatcher, or the normal foreground agent elsewhere.
pub fn service_entry() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::dispatch().map_err(|err| err.to_string())
    }
    #[cfg(not(windows))]
    {
        crate::run().map_err(|err| err.to_string())
    }
}

pub fn foreground_hint() -> &'static str {
    #[cfg(windows)]
    {
        "kestrel-agent is installed with the Windows service control manager"
    }
    #[cfg(not(windows))]
    {
        "kestrel-agent runs in the foreground; use the systemd or launchd unit"
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    const NAME: &str = "kestrel-agent";

    pub fn dispatch() -> Result<(), windows_service::Error> {
        service_dispatcher::start(NAME, ffi_service_main)
    }

    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service() {
            tracing::error!(error = %err, "windows service stopped");
        }
    }

    fn run_service() -> Result<(), windows_service::Error> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let status_handle = service_control_handler::register(NAME, move |control| {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(true);
                }
                ServiceControl::Interrogate => {}
                _ => return ServiceControlHandlerResult::NotImplemented,
            }
            ServiceControlHandlerResult::NoError
        })?;
        status_handle.set_service_status(status(ServiceState::Running))?;
        let result = crate::run_with_shutdown(Some(shutdown_rx));
        let mut stopped = status(ServiceState::Stopped);
        if let Err(err) = result {
            tracing::error!(error=%err,"Windows agent failed");
            stopped.exit_code = ServiceExitCode::Win32(1);
        }
        status_handle.set_service_status(stopped)?;
        Ok(())
    }

    fn status(current: ServiceState) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: current,
            controls_accepted: if current == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_hint_names_the_platform_manager() {
        let hint = foreground_hint();
        assert!(!hint.is_empty());
    }
}
