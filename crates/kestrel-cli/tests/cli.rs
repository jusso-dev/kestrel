use std::path::PathBuf;
use std::process::Command;

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kestrel-cli-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn token_create_prints_the_secret_once() {
    let dir = scratch("token");
    let output = Command::new(env!("CARGO_BIN_EXE_kestrel"))
        .args([
            "token",
            "create",
            "--group",
            "linux",
            "--ttl",
            "24h",
            "--data-dir",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let token = String::from_utf8(output.stdout).unwrap();
    let token = token.trim();
    assert!(token.len() >= 32, "{token}");
    assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
    let stored = std::fs::read_to_string(dir.join("enrolment.json")).unwrap();
    assert!(!stored.contains(token));
    let again = Command::new(env!("CARGO_BIN_EXE_kestrel"))
        .args([
            "token",
            "create",
            "--ttl",
            "30m",
            "--data-dir",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(again.status.success());
    let second = String::from_utf8(again.stdout).unwrap();
    assert_ne!(token, second.trim());
    let missing = Command::new(env!("CARGO_BIN_EXE_kestrel"))
        .args([
            "agent",
            "revoke",
            "00000000-0000-0000-0000-000000000000",
            "--data-dir",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}
