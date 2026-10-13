//! Restrict the agent private key to the service account and administrators.

use std::io;
use std::path::Path;

/// Write `pem` so only the service account and administrators can read it.
pub fn write_private_key(path: &Path, pem: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("key.tmp");
    write_secret(&tmp, pem)?;
    replace_file(&tmp, path)?;
    restrict_private_key(path)
}

/// Write a certificate. Certificates are not secret.
pub fn write_certificate(path: &Path, pem: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("crt.tmp");
    std::fs::write(&tmp, pem)?;
    replace_file(&tmp, path)
}

pub fn restrict_private_key(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        restrict_windows(path)
    }
}

fn write_secret(path: &Path, pem: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(pem.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(windows)]
    {
        std::fs::write(path, pem)?;
        Ok(())
    }
}

fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
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

#[cfg(windows)]
fn restrict_windows(path: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let user = current_windows_user()?;
    let grant_user = format!("{user}:(F)");
    let output = std::process::Command::new("icacls")
        .arg(path.as_os_str())
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
        ])
        .arg(grant_user)
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "icacls could not restrict the private key: {}",
            output_text(&output.stderr)
        )))
    }
}

#[cfg(windows)]
fn current_windows_user() -> io::Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = std::process::Command::new("whoami")
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("whoami failed"));
    }
    let name = output_text(&output.stdout).trim().to_string();
    if name.is_empty() {
        return Err(io::Error::other("whoami returned an empty name"));
    }
    Ok(name)
}

#[cfg(windows)]
pub(crate) fn output_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        return String::from_utf16_lossy(&utf16_le_units(&bytes[2..]));
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(windows)]
fn utf16_le_units(bytes: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    units
}
