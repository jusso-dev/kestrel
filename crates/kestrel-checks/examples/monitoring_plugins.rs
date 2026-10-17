//! Acceptance probe for unmodified Debian monitoring-plugins binaries.
//! Run through deploy/tests/Dockerfile.monitoring-plugins; no external targets.

use kestrel_checks::{run_command, CommandCheck};
use kestrel_proto::CheckState;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let plugins = vec![PathBuf::from("/usr/lib/nagios/plugins")];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let mut request = [0; 4096];
                    let _ = stream.read(&mut request)?;
                    stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )?;
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "plugin did not reach HTTP fixture",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    });
    for (id, command) in [
        (
            "disk",
            vec![
                "check_disk".to_string(),
                "-w".into(),
                "1%".into(),
                "-c".into(),
                "0%".into(),
                "-p".into(),
                "/".into(),
            ],
        ),
        (
            "http",
            vec![
                "check_http".to_string(),
                "-I".into(),
                "127.0.0.1".into(),
                "-p".into(),
                port.to_string(),
                "-u".into(),
                "/".into(),
                "-e".into(),
                "200".into(),
            ],
        ),
    ] {
        let check = CommandCheck {
            id: id.into(),
            command,
            timeout: Duration::from_secs(10),
            interval: Duration::from_secs(30),
        };
        let output = run_command(&check, &plugins, 1700000000000).await?;
        if output.state != CheckState::Ok {
            return Err(
                format!("check_{id} returned {:?}: {}", output.state, output.output).into(),
            );
        }
        let perf = output
            .samples
            .iter()
            .filter(|sample| sample.name == "kestrel_check_perf")
            .count();
        if output.perfdata.is_empty() || perf == 0 {
            return Err(
                format!("check_{id} did not produce parsed Nagios performance data").into(),
            );
        }
        println!("check_{id}: unmodified monitoring-plugins binary OK; parsed_perf_samples={perf}");
    }
    server.join().map_err(|_| "HTTP fixture thread failed")??;
    let denied = CommandCheck {
        id: "deny".into(),
        command: vec!["/bin/true".into()],
        timeout: Duration::from_secs(1),
        interval: Duration::from_secs(30),
    };
    if run_command(&denied, &plugins, 1700000000000).await.is_ok() {
        return Err("executable outside plugin directory was allowed".into());
    }
    println!("allowlist: executable outside plugin directory refused");
    Ok(())
}
