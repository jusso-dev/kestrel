//! Operator commands used by the `kestrel` CLI.

use crate::store::Directory;
use crate::ServerError;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

/// Create a one-time enrolment token and return the secret once.
pub fn create_token(
    data_dir: &Path,
    group: Option<String>,
    ttl: Duration,
) -> Result<String, ServerError> {
    let store = Directory::open(data_dir)?;
    let token = store.create_token(group, ttl)?;
    tracing::info!(data_dir = %data_dir.display(), "enrolment token created");
    Ok(token)
}

/// `kestrel-server admin create --email <email>`.
///
/// The password comes from `--password` or `KESTREL_ADMIN_PASSWORD`. It is
/// hashed with argon2id and is not included in errors or logs.
pub fn admin_cli(args: impl IntoIterator<Item = String>) -> Result<(), ServerError> {
    let args: Vec<String> = args.into_iter().collect();
    if args.first().map(String::as_str) != Some("admin")
        || args.get(1).map(String::as_str) != Some("create")
    {
        return Err(ServerError::new(
            "usage: kestrel-server admin create --email <email> [--password <password>] [--config <path>]",
        ));
    }
    let mut email = None;
    let mut password = None;
    let mut config = None;
    let mut iter = args.iter().skip(2);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--email" => email = iter.next().cloned(),
            "--password" => password = iter.next().cloned(),
            "--config" => config = iter.next().map(std::path::PathBuf::from),
            other => return Err(ServerError::new(format!("unknown argument {other}"))),
        }
    }
    let email = email.ok_or_else(|| ServerError::new("email is required"))?;
    if !email.contains('@') {
        return Err(ServerError::new("email is invalid"));
    }
    let password = password
        .or_else(|| std::env::var("KESTREL_ADMIN_PASSWORD").ok())
        .ok_or_else(|| ServerError::new("password is required"))?;
    if password.len() < 8 {
        return Err(ServerError::new("password must be at least 8 characters"));
    }
    let path = config
        .unwrap_or_else(|| crate::config::config_path_from_args(std::iter::empty::<String>()));
    let cfg = crate::config::load_server_config(&path)?;
    let hash = crate::passwords::hash_password(&password)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let db = crate::db::Db::connect(&cfg.database_url).await?;
        db.insert_user(
            &crate::db::TenantId::default_tenant(),
            crate::db::NewUser {
                email: email.clone(),
                password_hash: hash,
                role: "owner".to_string(),
                host_group_id: None,
            },
        )
        .await?;
        Ok::<(), crate::ServerError>(())
    })?;
    println!("created admin {email}");
    Ok(())
}

/// Mark an agent revoked. The next ingest or renew is rejected.
pub fn revoke_agent(data_dir: &Path, agent_id: Uuid) -> Result<(), ServerError> {
    let store = Directory::open(data_dir)?;
    store.revoke(agent_id)?;
    tracing::info!(%agent_id, "agent revoked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_create_error_does_not_include_the_password() {
        let err = admin_cli([
            "admin".to_string(),
            "create".to_string(),
            "--email".to_string(),
            "ops@example.com".to_string(),
            "--password".to_string(),
            "super-secret-value".to_string(),
            "--config".to_string(),
            "missing-server.toml".to_string(),
        ])
        .unwrap_err();
        assert!(!err.to_string().contains("super-secret-value"));
    }
}
