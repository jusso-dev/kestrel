//! `kestrel token create` and `kestrel agent revoke`.

use std::path::PathBuf;
use std::time::Duration;

fn main() {
    if let Err(err) = dispatch(std::env::args().skip(1)) {
        eprintln!("kestrel: {err}");
        std::process::exit(1);
    }
}

fn dispatch(args: impl IntoIterator<Item = String>) -> Result<(), CliError> {
    let args: Vec<String> = args.into_iter().collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
        println!("{}", usage());
        return Ok(());
    }
    match args[0].as_str() {
        "token" => token_command(&args[1..]),
        "agent" => agent_command(&args[1..]),
        other => Err(CliError::new(format!(
            "unknown command {other}\n{}",
            usage()
        ))),
    }
}

fn token_command(args: &[String]) -> Result<(), CliError> {
    if args.first().map(String::as_str) != Some("create") {
        return Err(CliError::new(format!("unknown token command\n{}", usage())));
    }
    let flags = parse_flags(&args[1..])?;
    if !flags.positionals.is_empty() {
        return Err(CliError::new(
            "token create does not take a positional argument",
        ));
    }
    let Some(ttl) = flags.ttl.as_deref() else {
        return Err(CliError::new(
            "token create requires --ttl, for example 24h",
        ));
    };
    let ttl = parse_ttl(ttl)?;
    let data_dir = resolve_data_dir(&flags)?;
    let token = kestrel_server::admin::create_token(&data_dir, flags.group, ttl)
        .map_err(|err| CliError::new(err.to_string()))?;
    println!("{token}");
    Ok(())
}

fn agent_command(args: &[String]) -> Result<(), CliError> {
    if args.first().map(String::as_str) != Some("revoke") {
        return Err(CliError::new(format!("unknown agent command\n{}", usage())));
    }
    let flags = parse_flags(&args[1..])?;
    if flags.positionals.len() != 1 {
        return Err(CliError::new("agent revoke requires one agent id"));
    }
    let agent_id = uuid::Uuid::parse_str(&flags.positionals[0])
        .map_err(|err| CliError::new(err.to_string()))?;
    let data_dir = resolve_data_dir(&flags)?;
    kestrel_server::admin::revoke_agent(&data_dir, agent_id)
        .map_err(|err| CliError::new(err.to_string()))?;
    println!("revoked {agent_id}");
    Ok(())
}

struct Flags {
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    group: Option<String>,
    ttl: Option<String>,
    positionals: Vec<String>,
}

fn parse_flags(args: &[String]) -> Result<Flags, CliError> {
    let mut flags = Flags {
        data_dir: None,
        config: None,
        group: None,
        ttl: None,
        positionals: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = arg.strip_prefix("--data-dir=") {
            flags.data_dir = Some(PathBuf::from(value));
        } else if arg == "--data-dir" {
            index += 1;
            flags.data_dir = Some(PathBuf::from(required(args, index, "--data-dir")?));
        } else if let Some(value) = arg.strip_prefix("--config=") {
            flags.config = Some(PathBuf::from(value));
        } else if arg == "--config" {
            index += 1;
            flags.config = Some(PathBuf::from(required(args, index, "--config")?));
        } else if let Some(value) = arg.strip_prefix("--group=") {
            flags.group = Some(value.to_string());
        } else if arg == "--group" {
            index += 1;
            flags.group = Some(required(args, index, "--group")?.to_string());
        } else if let Some(value) = arg.strip_prefix("--ttl=") {
            flags.ttl = Some(value.to_string());
        } else if arg == "--ttl" {
            index += 1;
            flags.ttl = Some(required(args, index, "--ttl")?.to_string());
        } else if arg.starts_with("--") {
            return Err(CliError::new(format!("unknown flag {arg}")));
        } else {
            flags.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(flags)
}

fn required<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, CliError> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| CliError::new(format!("{flag} requires a value")))
}

fn resolve_data_dir(flags: &Flags) -> Result<PathBuf, CliError> {
    if let Some(dir) = &flags.data_dir {
        return Ok(dir.clone());
    }
    let path = match &flags.config {
        Some(path) => path.clone(),
        None => kestrel_server::config::config_path_from_args(std::iter::empty::<String>()),
    };
    let cfg = kestrel_server::config::load_server_config(&path)
        .map_err(|err| CliError::new(err.to_string()))?;
    Ok(cfg.data_dir)
}

fn parse_ttl(text: &str) -> Result<Duration, CliError> {
    let text = text.trim();
    if text.len() < 2 {
        return Err(CliError::new("ttl must look like 24h, 30m, 1d, or 60s"));
    }
    let (number, unit) = text.split_at(text.len() - 1);
    let value: u64 = number
        .parse()
        .map_err(|_| CliError::new(format!("ttl must look like 24h, got {text}")))?;
    let seconds = match unit.to_ascii_lowercase().as_str() {
        "s" => value,
        "m" => value.saturating_mul(60),
        "h" => value.saturating_mul(60 * 60),
        "d" => value.saturating_mul(60 * 60 * 24),
        _ => {
            return Err(CliError::new(format!(
                "ttl must look like 24h, 30m, 1d, or 60s, got {text}"
            )))
        }
    };
    Ok(Duration::from_secs(seconds))
}

fn usage() -> &'static str {
    "kestrel token create --ttl 24h [--group NAME] [--data-dir PATH] [--config PATH]\n\
     kestrel agent revoke <id> [--data-dir PATH] [--config PATH]"
}

#[derive(Debug)]
struct CliError {
    message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_units() {
        assert_eq!(parse_ttl("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86_400));
        assert!(parse_ttl("24").is_err());
        assert!(parse_ttl("24x").is_err());
    }
}
