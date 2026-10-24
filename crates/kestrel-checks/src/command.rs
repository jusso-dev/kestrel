//! Nagios-compatible plugins and operator-configured scripts.
//!
//! The executable must resolve inside a plugin directory. The process is
//! spawned directly, with no shell, and is killed when the timeout fires.
//! On Unix the plugin leads its own process group, and the whole group is
//! killed on timeout or when the check future is dropped, so descendants do
//! not outlive it. On Windows only the direct child is killed (best effort
//! via `kill_on_drop`); descendants may survive.

use crate::perfdata::{parse_perfdata, PerfPoint};
use crate::sample;
use kestrel_proto::{CheckState, Sample};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

pub const STDOUT_CAP: usize = 4 * 1024;

pub struct CommandCheck {
    pub id: String,
    pub command: Vec<String>,
    pub timeout: Duration,
    pub interval: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommandOutput {
    pub state: CheckState,
    pub output: String,
    pub perfdata: String,
    pub samples: Vec<Sample>,
}

#[derive(Debug)]
pub struct CommandError {
    message: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

impl CommandError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Resolve `command[0]` to a canonical file inside one of `plugin_dirs`.
pub fn resolve_executable(
    command: &[String],
    plugin_dirs: &[PathBuf],
) -> Result<PathBuf, CommandError> {
    let exe = command
        .first()
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CommandError::new("command is empty"))?;
    if exe.contains('\0') {
        return Err(CommandError::new("command path is not allowed"));
    }
    let candidate = PathBuf::from(exe);
    let escapes = candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir));
    let resolved = if candidate.is_absolute() || escapes {
        canonical_file(&candidate)?
    } else if candidate.components().count() != 1 {
        return Err(CommandError::new(
            "relative commands must be a file name inside a plugin directory",
        ));
    } else {
        let mut found = None;
        for dir in plugin_dirs {
            let path = dir.join(&candidate);
            if let Ok(canonical) = canonical_file(&path) {
                found = Some(canonical);
                break;
            }
        }
        found.ok_or_else(|| CommandError::new("command is not in a plugin directory"))?
    };
    if !inside_plugin_dir(&resolved, plugin_dirs) {
        return Err(CommandError::new("command is not in a plugin directory"));
    }
    Ok(resolved)
}

fn canonical_file(path: &Path) -> Result<PathBuf, CommandError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| CommandError::new("command is not in a plugin directory"))?;
    if !canonical.is_file() {
        return Err(CommandError::new("command is not in a plugin directory"));
    }
    Ok(canonical)
}

fn inside_plugin_dir(exe: &Path, plugin_dirs: &[PathBuf]) -> bool {
    plugin_dirs.iter().any(|dir| {
        let Ok(root) = dir.canonicalize() else {
            return false;
        };
        exe.starts_with(&root) && exe != root
    })
}

/// Run `check` if its executable is inside `plugin_dirs`.
pub async fn run_command(
    check: &CommandCheck,
    plugin_dirs: &[PathBuf],
    now_ms: i64,
) -> Result<CommandOutput, CommandError> {
    let exe = resolve_executable(&check.command, plugin_dirs)?;
    let args = &check.command[1..];
    let mut command = Command::new(&exe);
    command
        .args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return Ok(unknown(
                check,
                &format!("could not start command: {err}"),
                now_ms,
            ))
        }
    };
    // Declared after `child` so it drops first, while the leader is unreaped
    // and its pid (the group id) cannot have been reused.
    let mut group = GroupKill::new(child.id());
    let timeout = check.timeout.max(Duration::from_millis(1));
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    // Drain both pipes concurrently, retaining only the cap. wait_with_output
    // would buffer arbitrary plugin output in memory before truncating it.
    // Reap the leader only after both pipes close: until then it stays a
    // zombie, so its pid (the group id) cannot be reused before a timeout kill.
    let collected = tokio::time::timeout(timeout, async {
        let (stdout, stderr) = tokio::try_join!(read_capped(stdout), read_capped(stderr))?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, stdout, stderr))
    })
    .await;
    let (status, stdout, stderr) = match collected {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            return Ok(unknown(
                check,
                &format!("could not read command output: {err}"),
                now_ms,
            ))
        }
        Err(_) => {
            group.kill();
            let _ = child.kill().await;
            return Ok(unknown(check, "timed out", now_ms));
        }
    };
    // The leader has been reaped; its pid may be reused from here on.
    group.disarm();
    let code = status.code().unwrap_or(3);
    let state = CheckState::from_exit_code(code);
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    if text.is_empty() {
        text = String::from_utf8_lossy(&stderr).into_owned();
    }
    let text = cap_output(&text);
    let (summary, perfdata) = split_output(&text);
    let points = parse_perfdata(perfdata).unwrap_or_default();
    let samples = samples_for(check, state, &points, now_ms);
    Ok(CommandOutput {
        state,
        output: summary.to_string(),
        perfdata: perfdata.to_string(),
        samples,
    })
}

/// Kills the plugin's process group when dropped unless disarmed.
struct GroupKill {
    #[cfg_attr(not(unix), allow(dead_code))]
    pgid: Option<u32>,
}

impl GroupKill {
    fn new(pid: Option<u32>) -> Self {
        Self { pgid: pid }
    }

    fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid.and_then(|pid| libc::pid_t::try_from(pid).ok()) {
            if pgid > 0 {
                // Safety: killpg only sends a signal. The group was created
                // by `process_group(0)` for this plugin and its leader is not
                // yet reaped, so the id still names that group.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
            }
        }
        self.pgid = None;
    }

    fn disarm(&mut self) {
        self.pgid = None;
    }
}

impl Drop for GroupKill {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn read_capped(mut reader: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::with_capacity(STDOUT_CAP);
    let mut chunk = [0u8; 4096];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        let keep = count.min(STDOUT_CAP.saturating_sub(retained.len()));
        retained.extend_from_slice(&chunk[..keep]);
    }
    Ok(retained)
}

fn unknown(check: &CommandCheck, output: &str, now_ms: i64) -> CommandOutput {
    CommandOutput {
        state: CheckState::Unknown,
        output: output.to_string(),
        perfdata: String::new(),
        samples: samples_for(check, CheckState::Unknown, &[], now_ms),
    }
}

fn cap_output(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.len() + ch.len_utf8() > STDOUT_CAP {
            break;
        }
        out.push(ch);
    }
    out
}

fn split_output(text: &str) -> (&str, &str) {
    match text.split_once('|') {
        Some((summary, perf)) => (summary.trim(), perf.trim()),
        None => (text.trim(), ""),
    }
}

fn samples_for(
    check: &CommandCheck,
    state: CheckState,
    points: &[PerfPoint],
    now_ms: i64,
) -> Vec<Sample> {
    let labels = [("check", check.id.as_str())];
    let mut samples = vec![sample(
        "kestrel_check_state",
        &labels,
        state as i32 as f64,
        now_ms,
    )];
    for point in points {
        samples.push(sample(
            "kestrel_check_perf",
            &[
                ("check", check.id.as_str()),
                ("label", point.label.as_str()),
                ("uom", point.uom.as_str()),
            ],
            point.value,
            now_ms,
        ));
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn command_drains_output_without_retaining_more_than_the_cap() {
        let bytes = read_capped(tokio::io::repeat(b'x').take((STDOUT_CAP * 100) as u64))
            .await
            .unwrap();
        assert_eq!(bytes.len(), STDOUT_CAP);
    }

    fn plugin_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kestrel-plugins-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn command_outside_plugin_dirs_is_refused() {
        let dir = plugin_dir("refuse");
        let err =
            resolve_executable(&["/bin/echo".to_string()], std::slice::from_ref(&dir)).unwrap_err();
        assert!(err.to_string().contains("plugin directory"), "{err}");
        let outside = dir.join("..").join("not-a-plugin");
        let err = resolve_executable(&[outside.display().to_string()], &[dir]).unwrap_err();
        assert!(err.to_string().contains("plugin directory"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_runs_a_fixture_inside_the_plugin_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = plugin_dir("fixture");
        let script = dir.join("check_ok.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'OK | used=85%;90;95;0;100'\nexit 0\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        let check = CommandCheck {
            id: "disk".to_string(),
            command: vec![script.display().to_string()],
            timeout: Duration::from_secs(10),
            interval: Duration::from_secs(60),
        };
        let output = run_command(&check, std::slice::from_ref(&dir), 1_700_000_000_000)
            .await
            .unwrap();
        assert_eq!(output.state, CheckState::Ok);
        assert!(output.output.contains("OK"));
        assert!(output.perfdata.contains("used=85%"));
        assert!(output
            .samples
            .iter()
            .any(|sample| sample.name == "kestrel_check_perf"));
        let sleeper = dir.join("check_sleep.sh");
        std::fs::write(&sleeper, "#!/bin/sh\nsleep 5\n").unwrap();
        let mut perms = std::fs::metadata(&sleeper).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&sleeper, perms).unwrap();
        let slow = CommandCheck {
            id: "slow".to_string(),
            command: vec![sleeper.display().to_string()],
            timeout: Duration::from_millis(200),
            interval: Duration::from_secs(60),
        };
        let output = run_command(&slow, std::slice::from_ref(&dir), 1_700_000_000_000)
            .await
            .unwrap();
        assert_eq!(output.state, CheckState::Unknown);
        assert_eq!(output.output, "timed out");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    fn spawner(dir: &Path, pid_file: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("check_spawn.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nsleep 30 &\necho $! > '{}'\nsleep 30\n",
                pid_file.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script
    }

    #[cfg(unix)]
    async fn wait_for_pid(pid_file: &Path) -> libc::pid_t {
        for _ in 0..1000 {
            if let Ok(text) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = text.trim().parse() {
                    return pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("plugin did not record its background pid");
    }

    #[cfg(unix)]
    async fn assert_gone(pid: libc::pid_t) {
        for _ in 0..1000 {
            // Safety: signal 0 only checks that the pid exists.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant {pid} survived the plugin");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_timeout_kills_plugin_descendants() {
        let dir = plugin_dir("descendants-timeout");
        let pid_file = dir.join("bg.pid");
        let check = CommandCheck {
            id: "spawn".to_string(),
            command: vec![spawner(&dir, &pid_file).display().to_string()],
            timeout: Duration::from_secs(5),
            interval: Duration::from_secs(60),
        };
        let output = run_command(&check, std::slice::from_ref(&dir), 1)
            .await
            .unwrap();
        assert_eq!(output.output, "timed out");
        assert_gone(wait_for_pid(&pid_file).await).await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_cancellation_kills_plugin_descendants() {
        let dir = plugin_dir("descendants-cancel");
        let pid_file = dir.join("bg.pid");
        let check = CommandCheck {
            id: "spawn".to_string(),
            command: vec![spawner(&dir, &pid_file).display().to_string()],
            timeout: Duration::from_secs(60),
            interval: Duration::from_secs(60),
        };
        let dirs = [dir.clone()];
        let mut running = Box::pin(run_command(&check, &dirs, 1));
        let pid = tokio::select! {
            _ = &mut running => panic!("plugin finished early"),
            pid = wait_for_pid(&pid_file) => pid,
        };
        drop(running);
        assert_gone(pid).await;
        let _ = std::fs::remove_dir_all(dir);
    }
}
