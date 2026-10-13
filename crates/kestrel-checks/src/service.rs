//! Service up/down gauges.
//!
//! Linux reads systemd `ActiveState` on the system bus. Windows asks the
//! Service Control Manager. macOS parses `launchctl print`. A service that is
//! not installed is down. Each collect reads the live state, so a stop is
//! visible on the next interval. Windows Event Log and journald are not read
//! here.

use crate::metrics::SERVICE_UP;
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

pub struct ServiceCollector {
    names: Vec<String>,
    interval: Duration,
    query: StatusQuery,
}

enum StatusQuery {
    Platform,
    #[cfg(test)]
    Override(Arc<dyn Fn(&str) -> bool + Send + Sync>),
}

impl ServiceCollector {
    pub fn new(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            names: normalise_names(names),
            interval: DEFAULT_INTERVAL,
            query: StatusQuery::Platform,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_query<F>(
        names: impl IntoIterator<Item = impl Into<String>>,
        query: F,
    ) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        Self {
            names: normalise_names(names),
            interval: DEFAULT_INTERVAL,
            query: StatusQuery::Override(Arc::new(query)),
        }
    }

    fn is_up(&self, name: &str) -> Result<bool, CollectError> {
        match &self.query {
            StatusQuery::Platform => platform_is_up(name),
            #[cfg(test)]
            StatusQuery::Override(query) => Ok(query(name)),
        }
    }
}

impl Default for ServiceCollector {
    fn default() -> Self {
        Self::new(Vec::<String>::new())
    }
}

impl Collector for ServiceCollector {
    fn name(&self) -> &str {
        "service"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        let mut samples = Vec::with_capacity(self.names.len());
        for name in &self.names {
            let up = self.is_up(name)?;
            samples.push(sample(
                SERVICE_UP,
                &[("name", name.as_str())],
                if up { 1.0 } else { 0.0 },
                now_ms,
            ));
        }
        Ok(samples)
    }
}

fn normalise_names(names: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        let name = name.into();
        if name.is_empty() || out.iter().any(|existing| existing == &name) {
            continue;
        }
        out.push(name);
    }
    out
}

/// `nginx` becomes `nginx.service`. Names that already carry a unit suffix
/// are left alone.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn systemd_unit_name(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

#[cfg(any(test, target_os = "macos"))]
pub(crate) fn launchctl_target(name: &str) -> String {
    if name.contains('/') {
        name.to_string()
    } else {
        format!("system/{name}")
    }
}

/// `launchctl print` marks a running job with `state = running`.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn launchctl_is_running(text: &str) -> bool {
    text.lines().any(|line| {
        line.trim()
            .strip_prefix("state =")
            .is_some_and(|rest| rest.trim() == "running")
    })
}

fn platform_is_up(name: &str) -> Result<bool, CollectError> {
    #[cfg(target_os = "linux")]
    {
        systemd::is_up(name)
    }
    #[cfg(windows)]
    {
        windows::is_up(name)
    }
    #[cfg(target_os = "macos")]
    {
        launchd::is_up(name)
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = name;
        Err(CollectError::new(
            "service status is not available on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
mod systemd {
    use super::CollectError;

    // Only the blocking proxy is generated. With `gen_async = false` the
    // type is `*Proxy`, not `*ProxyBlocking`.
    #[zbus::proxy(
        interface = "org.freedesktop.systemd1.Manager",
        default_service = "org.freedesktop.systemd1",
        default_path = "/org/freedesktop/systemd1",
        gen_async = false
    )]
    trait SystemdManager {
        fn get_unit(&self, name: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.systemd1.Unit",
        default_service = "org.freedesktop.systemd1",
        gen_async = false
    )]
    trait SystemdUnit {
        #[zbus(property)]
        fn active_state(&self) -> zbus::Result<String>;
    }

    pub(super) fn is_up(name: &str) -> Result<bool, CollectError> {
        let unit = super::systemd_unit_name(name);
        let connection = zbus::blocking::Connection::system()
            .map_err(|err| CollectError::new(format!("systemd bus: {err}")))?;
        let manager = SystemdManagerProxy::new(&connection)
            .map_err(|err| CollectError::new(format!("systemd manager: {err}")))?;
        let path = match manager.get_unit(&unit) {
            Ok(path) => path,
            Err(err) if unit_is_missing(&err) => return Ok(false),
            Err(err) => {
                return Err(CollectError::new(format!("systemd GetUnit {unit}: {err}")));
            }
        };
        let unit_proxy = SystemdUnitProxy::builder(&connection)
            .path(&path)
            .map_err(|err| CollectError::new(format!("systemd unit path: {err}")))?
            .build()
            .map_err(|err| CollectError::new(format!("systemd unit: {err}")))?;
        let state = unit_proxy
            .active_state()
            .map_err(|err| CollectError::new(format!("systemd ActiveState: {err}")))?;
        Ok(state == "active")
    }

    fn unit_is_missing(err: &zbus::Error) -> bool {
        let text = err.to_string();
        text.contains("NoSuchUnit") || text.contains("not loaded")
    }
}

#[cfg(windows)]
mod windows {
    use super::CollectError;
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    const ERROR_INVALID_NAME: i32 = 123;
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    pub(super) fn is_up(name: &str) -> Result<bool, CollectError> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|err| CollectError::new(format!("service manager: {err}")))?;
        match manager.open_service(name, ServiceAccess::QUERY_STATUS) {
            Ok(service) => {
                let status = service
                    .query_status()
                    .map_err(|err| CollectError::new(format!("service {name} status: {err}")))?;
                Ok(status.current_state == ServiceState::Running)
            }
            Err(err) if service_is_absent(&err) => Ok(false),
            Err(err) => Err(CollectError::new(format!("service {name}: {err}"))),
        }
    }

    fn service_is_absent(err: &windows_service::Error) -> bool {
        match err {
            windows_service::Error::Winapi(io) => {
                matches!(
                    io.raw_os_error(),
                    Some(ERROR_SERVICE_DOES_NOT_EXIST | ERROR_INVALID_NAME)
                )
            }
            _ => false,
        }
    }
}

#[cfg(target_os = "macos")]
mod launchd {
    use super::{launchctl_is_running, launchctl_target, CollectError};
    use std::process::Command;

    pub(super) fn is_up(name: &str) -> Result<bool, CollectError> {
        let target = launchctl_target(name);
        let output = Command::new("launchctl")
            .arg("print")
            .arg(&target)
            .output()
            .map_err(|err| CollectError::new(format!("launchctl print {target}: {err}")))?;
        if !output.status.success() {
            return Ok(false);
        }
        Ok(launchctl_is_running(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn label<'a>(sample: &'a Sample, key: &str) -> Option<&'a str> {
        sample
            .labels
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn stopping_a_monitored_service_flips_kestrel_service_up_to_zero_within_one_interval() {
        let up = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&up);
        let mut collector = ServiceCollector::with_query(["kestrel-demo"], move |name| {
            assert_eq!(name, "kestrel-demo");
            flag.load(Ordering::SeqCst)
        });
        let interval_ms = i64::try_from(collector.interval().as_millis()).unwrap();
        assert_eq!(collector.interval(), DEFAULT_INTERVAL);

        let started = 1_700_000_000_000;
        let first = collector.collect(started).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].name, SERVICE_UP);
        assert_eq!(label(&first[0], "name"), Some("kestrel-demo"));
        assert_eq!(first[0].value, 1.0);
        assert_eq!(first[0].timestamp_ms, started);

        up.store(false, Ordering::SeqCst);
        let second = collector.collect(started + interval_ms).unwrap();
        assert_eq!(second[0].value, 0.0);
        assert_eq!(second[0].timestamp_ms - first[0].timestamp_ms, interval_ms);
        assert_eq!(label(&second[0], "name"), Some("kestrel-demo"));
    }

    #[test]
    fn systemd_and_launchctl_names() {
        assert_eq!(systemd_unit_name("nginx"), "nginx.service");
        assert_eq!(systemd_unit_name("nginx.service"), "nginx.service");
        assert_eq!(systemd_unit_name("user.slice"), "user.slice");
        assert_eq!(
            launchctl_target("com.example.demo"),
            "system/com.example.demo"
        );
        assert_eq!(
            launchctl_target("system/com.example.demo"),
            "system/com.example.demo"
        );
        let running = "system/com.example.demo = {\n\tstate = running\n}\n";
        let stopped = "\tstate = not running\n";
        assert!(launchctl_is_running(running));
        assert!(!launchctl_is_running(stopped));
        assert!(!launchctl_is_running("state = spawn scheduled\n"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_scm_reports_a_running_service_and_a_missing_one() {
        let mut collector = ServiceCollector::new(["EventLog", "KestrelMissingServiceXYZ"]);
        let samples = collector.collect(1).expect("scm query");
        assert_eq!(samples.len(), 2);
        assert_eq!(label(&samples[0], "name"), Some("EventLog"));
        assert_eq!(samples[0].value, 1.0, "EventLog should be running");
        assert_eq!(label(&samples[1], "name"), Some("KestrelMissingServiceXYZ"));
        assert_eq!(samples[1].value, 0.0);
    }
}
