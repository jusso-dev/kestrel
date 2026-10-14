# Agent

The agent pushes samples over mutual TLS. It enrols once with a token, then renews its certificate.

```sh
kestrel token create --ttl 1h
```

Put the token in `enrol_token` and start `kestrel-agent`. The token is shown once and only its hash is stored.

## Config the server sends

The agent polls `GET /api/v1/agent/config` every 60 seconds with `If-None-Match`. A 304 means the desired config is unchanged. Builtin collectors (CPU, memory, filesystem, network) do not need a script.

## Scripts and Nagios plugins

`allow_remote_commands` defaults to false. A template item of kind `command` runs only when that flag is true and the executable is inside `plugin_dirs` (default `/usr/lib/kestrel/plugins` and `/usr/lib/nagios/plugins`). The path is canonicalised. Anything outside those directories is refused. The agent does not use a shell.

HTTP checks and builtin collectors are not shell commands. Linking the Linux template does not enable remote execution.

## Prometheus

`prometheus_listen` must be a loopback address, for example `127.0.0.1:9469`. Other bind addresses are ignored.

## Services

- Linux: `deploy/systemd/kestrel-agent.service`
- macOS: `deploy/launchd/au.jusso-dev.kestrel-agent.plist`
- Windows: the `windows-service` entry in `crates/kestrel-agent/src/service.rs`
