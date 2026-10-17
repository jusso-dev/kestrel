//! Discover entities locally and periodically send inventory through the WAL.

use crate::buffer::Buffer;
use kestrel_proto::v1;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

fn command_output(program: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped inventory output");
    let (tx, rx) = std::sync::mpsc::channel();
    // Drain while the command runs. A pipe must not fill before try_wait;
    // neither retained output nor a stuck pipe reader may block shutdown.
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .take(1024 * 1024)
            .read_to_end(&mut output)
            .map(|_| output);
        let _ = tx.send(result);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inventory command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(std::io::Error::other("inventory command failed"));
    }
    rx.recv_timeout(Duration::from_millis(100)).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "inventory output timed out")
    })?
}

pub fn collect() -> v1::Inventory {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut filesystems: Vec<_> = disks
        .iter()
        .map(|disk| v1::Filesystem {
            mount: disk.mount_point().to_string_lossy().into_owned(),
            device: disk.name().to_string_lossy().into_owned(),
            fs_type: disk.file_system().to_string_lossy().into_owned(),
        })
        .collect();
    filesystems.sort_by(|a, b| a.mount.cmp(&b.mount));
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let mut interfaces: Vec<_> = networks
        .iter()
        .map(|(name, net)| v1::NetInterface {
            name: name.clone(),
            mac: net.mac_address().to_string(),
            addresses: net.ip_networks().iter().map(ToString::to_string).collect(),
        })
        .collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    v1::Inventory {
        filesystems,
        interfaces,
        listen_ports: listening_ports(),
        services: services(),
    }
}

fn listening_ports() -> Vec<v1::ListenPort> {
    #[cfg(target_os = "linux")]
    {
        let mut ports = Vec::new();
        for (path, protocol) in [
            ("/proc/net/tcp", "tcp"),
            ("/proc/net/tcp6", "tcp"),
            ("/proc/net/udp", "udp"),
            ("/proc/net/udp6", "udp"),
        ] {
            if let Ok(text) = std::fs::read_to_string(path) {
                for line in text.lines().skip(1) {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields.len() < 4 || (protocol == "tcp" && fields[3] != "0A") {
                        continue;
                    }
                    if let Some((address, port)) = fields[1].split_once(':') {
                        if let Ok(port) = u32::from_str_radix(port, 16) {
                            ports.push(v1::ListenPort {
                                address: decode_address(address),
                                port,
                                protocol: protocol.into(),
                            });
                        }
                    }
                }
            }
        }
        ports.sort_by(|a, b| {
            (&a.protocol, &a.address, a.port).cmp(&(&b.protocol, &b.address, b.port))
        });
        ports.dedup();
        ports
    }
    #[cfg(not(target_os = "linux"))]
    {
        platform_ports()
    }
}

#[cfg(target_os = "linux")]
fn decode_address(hex: &str) -> String {
    if !matches!(hex.len(), 8 | 32) {
        return hex.to_string();
    }
    let mut bytes = Vec::with_capacity(16);
    for start in (0..hex.len()).step_by(8) {
        let Some(word) = hex
            .get(start..start + 8)
            .and_then(|part| u32::from_str_radix(part, 16).ok())
        else {
            return hex.to_string();
        };
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    match bytes.as_slice() {
        [a, b, c, d] => std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string(),
        bytes if bytes.len() == 16 => {
            let mut addr = [0; 16];
            addr.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => hex.to_string(),
    }
}

#[cfg(not(target_os = "linux"))]
fn platform_ports() -> Vec<v1::ListenPort> {
    // lsof's field output does not depend on translated column headings.
    #[cfg(target_os = "macos")]
    if let Ok(out) = command_output("/usr/sbin/lsof", &["-nP", "-iTCP", "-sTCP:LISTEN", "-Fn"]) {
        let mut ports: Vec<_> = String::from_utf8_lossy(&out)
            .lines()
            .filter_map(|line| {
                let endpoint = line.strip_prefix('n')?;
                let (address, port) = endpoint.rsplit_once(':')?;
                Some(v1::ListenPort {
                    address: address.trim_matches(['[', ']']).into(),
                    port: port.parse().ok()?,
                    protocol: "tcp".into(),
                })
            })
            .collect();
        ports.sort_by(|a, b| (&a.address, a.port).cmp(&(&b.address, b.port)));
        ports.dedup();
        return ports;
    }
    #[cfg(windows)]
    if let Ok(out) = command_output("netstat.exe", &["-an", "-p", "tcp"]) {
        let mut ports: Vec<_> = String::from_utf8_lossy(&out)
            .lines()
            .filter_map(|line| {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() < 4 || f[0] != "TCP" || f[3] != "LISTENING" {
                    return None;
                }
                let (address, port) = f[1].rsplit_once(':')?;
                Some(v1::ListenPort {
                    address: address.trim_matches(['[', ']']).into(),
                    port: port.parse().ok()?,
                    protocol: "tcp".into(),
                })
            })
            .collect();
        ports.sort_by(|a, b| (&a.address, a.port).cmp(&(&b.address, b.port)));
        ports.dedup();
        return ports;
    }
    vec![]
}

fn services() -> Vec<v1::Service> {
    #[cfg(target_os = "linux")]
    let (program, args, manager) = (
        "systemctl",
        vec![
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        "systemd",
    );
    #[cfg(target_os = "macos")]
    let (program, args, manager) = ("/bin/launchctl", vec!["list"], "launchd");
    #[cfg(windows)]
    let (program, args, manager) = (
        "sc.exe",
        vec!["query", "type=", "service", "state=", "all"],
        "scm",
    );
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        if let Ok(out) = command_output(program, &args) {
            let text = String::from_utf8_lossy(&out);
            let mut result = Vec::new();
            #[cfg(target_os = "linux")]
            for line in text.lines() {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() >= 4 {
                    result.push(v1::Service {
                        name: f[0].into(),
                        manager: manager.into(),
                        state: f[2].into(),
                    });
                }
            }
            #[cfg(target_os = "macos")]
            for line in text.lines().skip(1) {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() >= 3 {
                    result.push(v1::Service {
                        name: f[2].into(),
                        manager: manager.into(),
                        state: if f[0] == "-" { "inactive" } else { "active" }.into(),
                    });
                }
            }
            #[cfg(windows)]
            {
                let mut name = None;
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(n) = line.strip_prefix("SERVICE_NAME:") {
                        name = Some(n.trim().to_string());
                    } else if line.starts_with("STATE") {
                        if let Some(n) = name.take() {
                            result.push(v1::Service {
                                name: n,
                                manager: manager.into(),
                                state: if line.contains("RUNNING") {
                                    "active"
                                } else {
                                    "inactive"
                                }
                                .into(),
                            });
                        }
                    }
                }
            }
            result.sort_by(|a, b| a.name.cmp(&b.name));
            return result;
        }
    }
    vec![]
}

pub async fn run(
    buffer: Arc<Mutex<Buffer>>,
    agent_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous = None;
    let mut last_sent = tokio::time::Instant::now() - Duration::from_secs(600);
    loop {
        tokio::select! {
            _=shutdown.changed()=>break,
            _=tick.tick()=>{
            let inventory=tokio::select! {
                _=shutdown.changed()=>break,
                result=tokio::task::spawn_blocking(collect)=>match result {Ok(v)=>v,Err(_)=>continue},
            };
                if previous.as_ref()!=Some(&inventory)||last_sent.elapsed()>=Duration::from_secs(600) {
                    let batch=v1::Batch{agent_id:agent_id.clone(),inventory:Some(inventory.clone()),..Default::default()};
                    match buffer.lock().unwrap_or_else(|err|err.into_inner()).append(&batch) {
                        Ok(())=>{previous=Some(inventory);last_sent=tokio::time::Instant::now();},
                        Err(err)=>tracing::warn!(error=%err,"could not buffer inventory"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn inventory_commands_have_a_deadline() {
        let start = std::time::Instant::now();
        let error = command_output("/bin/sh", &["-c", "exec sleep 10"]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert_eq!(command_output("/bin/echo", &["ready"]).unwrap(), b"ready\n");
    }
    #[test]
    fn inventory_has_stably_sorted_host_entities() {
        let inventory = collect();
        assert!(!inventory.filesystems.is_empty());
        assert!(inventory
            .filesystems
            .windows(2)
            .all(|p| p[0].mount <= p[1].mount));
        assert!(inventory
            .interfaces
            .windows(2)
            .all(|p| p[0].name <= p[1].name));
    }
}
