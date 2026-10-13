# Kestrel architecture

## Components

```
+-------------+   mTLS HTTP/2 (protobuf, zstd)   +-----------------------------+
| kestrel-    | -------------------------------> | kestrel-server              |
| agent       |   POST /api/v1/ingest            |  ingest -> VictoriaMetrics  |
| (per host)  | <------------------------------- |  rules engine (evaluator)   |
+-------------+   config + checks (GET, ETag)    |  notifier, escalations      |
                                                 |  REST API + web UI          |
SNMP devices <---- pollers (server side) ------- |  PostgreSQL (config, state) |
HTTP targets <---- synthetic checks ------------ |  SIEM forwarder (optional)  |
OTLP clients ----> /v1/metrics ----------------> +-----------------------------+
```

## Agent

- Single static binary built with `--target x86_64-unknown-linux-musl`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin` and friends.
- Collectors live in `kestrel-checks` and implement `Collector::collect(&mut self) -> Vec<Sample>`. System data comes from the `sysinfo` crate, with platform extras behind `cfg`.
- A `Scheduler` runs each collector at its interval on a tokio runtime.
- Samples go into a `Buffer` (an append-only segment log on disk under the data dir, capped by size) and a `Shipper` drains it to the server. If the server is unreachable the buffer keeps filling and ships later in order.
- Identity: on first start the agent creates a key pair and a CSR, and enrols with a one-time token. The server signs a client certificate. All later traffic uses that certificate.
- Runs as an unprivileged `kestrel` user on Linux (with `CAP_DAC_READ_SEARCH` only if log tailing needs it), a virtual service account on Windows, and a launchd daemon user on macOS.

## Server

- `axum` HTTP server with `rustls`. Ingest, API and UI on one port by default, ingest can be split onto its own port that requires client certificates.
- Config and state in PostgreSQL through `sqlx` with compile-time checked queries and migrations in `crates/kestrel-server/migrations`.
- Metrics written to VictoriaMetrics with the Prometheus remote write protocol, read back with PromQL or MetricsQL over HTTP. A `MetricStore` trait keeps this swappable.
- Rules engine: every trigger is an expression (PromQL subset) evaluated on a schedule. State machine per trigger and host: `Ok -> Pending -> Problem -> Resolved`, with `for` durations and hysteresis.
- Notifier: a queue table in PostgreSQL (`notification_jobs`) drained by workers, so alerts survive restarts.
- Web UI: SvelteKit built as static files and embedded in the server binary with `rust-embed`.

## Tenancy and RBAC

Every config row has a `tenant_id`. Every metric is written with a `tenant` label. API handlers extract a `TenantContext` from the session and all queries filter on it. Roles: `owner`, `admin`, `operator`, `viewer`, scoped to a tenant and optionally to host groups.

## Security

- mTLS for agents, TLS for UI, no plaintext mode except an explicit `--insecure-dev` flag.
- Passwords hashed with argon2id. API tokens are random, stored hashed.
- Agents never accept inbound connections by default (push model). Remote commands are disabled unless explicitly allowed per host.
