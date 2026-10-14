# Kestrel

Open-source infrastructure monitoring in Rust. One small agent, one server, no PHP, no Perl. Kestrel aims to replace Zabbix and Nagios with something you can install in five minutes and trust on the internet.

> Status: pre-alpha. The workspace compiles, and features are being built from the [roadmap](#roadmap). See the pinned roadmap issue.

## Vision

Zabbix and Nagios run a huge share of the world's monitoring, but they show their age: heavy setup, legacy web UIs, plaintext agents and C codebases with long CVE histories. Kestrel keeps what people love (agents, templates, triggers, Nagios plugins) and adds what they now expect: mTLS by default, Prometheus and OpenTelemetry compatibility, multi-tenancy for MSPs and a modern web UI. Events can be forwarded to a SIEM such as [Wedgetail](https://github.com/yumaitau/wedgetail).

## Features (planned for v1)

**Agent** (`kestrel-agent`, one static binary for Linux, Windows and macOS)
- CPU, memory, disk, filesystem, network, processes, services and log tailing
- Runs existing Nagios plugins and custom scripts
- Exposes and scrapes the Prometheus exposition format
- Push over mTLS with an on-disk offline buffer
- Auto-discovery of disks, interfaces and services
- Runs with minimal privileges

**Server** (`kestrel-server`, axum)
- Time series storage via VictoriaMetrics (see ADR 0002), config in PostgreSQL
- Triggers and alert rules, escalations and acknowledgements
- Notifications: email, Slack, Microsoft Teams, webhook, PagerDuty
- Maintenance windows, host groups, templates
- SNMP polling, HTTP and synthetic checks
- Dashboards in a web UI
- Multi-tenancy and RBAC, REST API
- OpenTelemetry (OTLP) metrics ingest
- Optional event forwarding to a SIEM (Wedgetail, syslog, webhook)

## Architecture

```
crates/
  kestrel-proto   wire types shared by agent and server
  kestrel-checks  collectors and check runners used by the agent
  kestrel-agent   the agent binary
  kestrel-server  the axum server, rules engine, notifier
  kestrel-cli     admin CLI (`kestrel`)
web/              the web UI (added in M1)
```

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/adr](docs/adr).

## Docs

- [Quick start](docs/quickstart.md)
- [Agent](docs/agent.md)
- [Triggers](docs/triggers.md)
- [Operations](docs/operations.md)
- [Roles](docs/rbac.md)
- [Wedgetail](docs/integrations/wedgetail.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## Roadmap

- **M0 Skeleton:** workspace, config, protocol, dev stack
- **M1 MVP:** agent core metrics, mTLS push, server ingest, storage, triggers, email and webhook alerts, basic UI
- **M2 Parity:** templates, host groups, discovery, SNMP, HTTP checks, Nagios plugins, escalations, maintenance, RBAC, more notifiers
- **M3 Beyond:** multi-tenancy, OTLP, SIEM forwarding, synthetic checks, HA

## Licence

MIT. See [LICENSE](LICENSE).
