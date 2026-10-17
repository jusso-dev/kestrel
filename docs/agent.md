# Agent

The agent enrols once with a short-lived token, then pushes over mutual TLS and renews its certificate. Keep the token in a protected file until bootstrap; stdin keeps it out of command-line arguments and terminal history.

```sh
umask 077
kestrel token create --ttl 1h --data-dir /var/lib/kestrel > ./kestrel-enrol-token
```

Run this on the server, adjusting `--data-dir` to its configured directory. The token is written once to the protected file; only its hash is stored on the server.

## First-run configuration

`--configure --server URL --token-stdin` writes the platform's configuration with owner-only permissions (Windows: the current account, SYSTEM and administrators). It refuses to replace an existing configuration. `--config PATH` and `--data-dir PATH` override the defaults. Use HTTPS for enrolment. Run configuration as root or an elevated administrator.

For Kestrel's private server certificate, add `--ca-file /secure/server-ca.crt` to the configure command. Obtain this public CA certificate through a trusted channel before enrolment. It is copied beside the configuration and referenced by `bootstrap_ca_path`; the token is sent only after TLS server verification succeeds. Servers with a publicly trusted certificate can omit this option.

Linux, after installing the binary and systemd unit:

```sh
sudo kestrel-agent --configure --server https://monitor.example --token-stdin < /secure/enrol-token
sudo chown root:kestrel /etc/kestrel/agent.toml
sudo chmod 640 /etc/kestrel/agent.toml
sudo chown kestrel:kestrel /var/lib/kestrel
sudo chmod 750 /var/lib/kestrel
sudo systemctl enable --now kestrel-agent
```

The default configuration is `/etc/kestrel/agent.toml`; data is under `/var/lib/kestrel`. These commands assume the `kestrel` service account and unit have been installed. The Linux installer performs this ownership setup automatically.

macOS, after installing the signed package:

```sh
sudo /usr/local/bin/kestrel-agent --configure --server https://monitor.example --token-stdin < /secure/enrol-token
sudo launchctl bootstrap system /Library/LaunchDaemons/au.jusso-dev.kestrel-agent.plist
sudo launchctl kickstart system/au.jusso-dev.kestrel-agent
```

Configuration and data default to `/Library/Application Support/Kestrel`; `agent.toml` is the configuration file. The package installs the launchd job; bootstrap it after configuring this host.

Windows, in an elevated PowerShell after installing the MSI:

```powershell
Get-Content -Raw C:\Secure\enrol-token | & 'C:\Program Files\Kestrel\kestrel-agent.exe' --configure --server https://monitor.example --token-stdin
if ($LASTEXITCODE -ne 0) { throw 'Agent configuration failed' }
Set-Service kestrel-agent -StartupType Automatic
Start-Service kestrel-agent
```

The MSI creates a demand-start service so fresh installations do not launch before configuration exists. Configuration and data default to `C:\ProgramData\Kestrel`. Remove the temporary token file once enrolment succeeds. A token may remain in the protected configuration; the agent uses its saved certificate after enrolment.

## Config the server sends

The agent polls `GET /api/v1/agent/config` at startup and at most every 60 seconds with `If-None-Match`. A 304 preserves the running schedule. Changed configuration replaces schedules without restarting the process. Core collectors continue while the server is unavailable; linked templates override intervals and add HTTP, Prometheus, command, and log checks. Inventory is sent on detected changes and at least every ten minutes through the offline buffer.

## Scripts and Nagios plugins

`allow_remote_commands` defaults to false and `plugin_dirs` defaults to empty. Set both explicitly to enable commands:

```toml
allow_remote_commands = true
plugin_dirs = ["/usr/lib/kestrel/plugins", "/usr/lib/nagios/plugins"]
```

The executable's canonical path must remain inside an allowed directory. The agent starts it directly without a shell, enforces timeouts, and retains at most 4 KiB per output stream. Plugin exit states and performance metrics are buffered for delivery. Keep plugin directories writable only by administrators. Remote log specifications are trusted server configuration and can read files accessible to the service account.

HTTP checks and builtin collectors are not shell commands. Linking the Linux template does not enable remote execution.

## Prometheus

Set `prometheus_listen = "127.0.0.1:9469"` to expose the latest samples at `/metrics`. Only a loopback socket address or `localhost:PORT` is accepted; invalid addresses produce a listener error. Scrape items use kind `prometheus` and params `url`, `job`, and `instance`; conflicting target identity labels are preserved under `exported_` names. HTTP checks report status, duration, body match and the TLS leaf certificate's expiry. URLs with embedded credentials are rejected; query strings are omitted from metric target labels. Scrapes retain other metrics when an exporter reports `NaN` or infinity for an unavailable observation. Hosts without an enrolled agent can run linked HTTP and Prometheus items through the server's bounded poller.

## Services

- Linux: `deploy/systemd/kestrel-agent.service`
- macOS: `deploy/launchd/au.jusso-dev.kestrel-agent.plist`
- Windows: the MSI installs `--service`; the runtime responds to SCM stop and shutdown requests and flushes its buffer.
