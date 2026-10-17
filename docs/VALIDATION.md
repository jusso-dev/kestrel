# Validation record

Acceptance work recorded on 17 October 2026. Tests used isolated, disposable PostgreSQL 16, VictoriaMetrics v1.111.0, Mailpit and SNMP fixtures. No production monitoring data or device credentials were used.

## Runtime and security

The server now uses PostgreSQL for API resources, sessions, audit records, ingest sequence numbers and worker queues. Trigger evaluation, notification delivery, forwarding, agentless checks and security outbox replay run as independent background workers. Agent configuration polling, scheduled checks, inventory delivery and loopback Prometheus exposition run in the agent process.

The integration tests exercise database persistence, tenant and host-group isolation, role checks, template inheritance, discovery ageing, maintenance, escalation acknowledgement, restart deduplication, queue retries and security outbox replay. SMTP delivery uses a real Mailpit fixture; the syslog test verifies TLS trust rejection, an explicitly trusted CA and RFC 5425 octet framing. Notification template tests cover bounded output and rejection of executable template expressions.

Final Linux checks passed: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. The workspace run passed **147 tests**, with zero failures and two ignored external SNMP tests; both SNMP tests passed separately against the simulator. The PostgreSQL, VictoriaMetrics and Mailpit environment variables were set during the full run, so those integration checks executed.

A container smoke test created an administrator with the CLI, signed in through the persisted HTTPS session API, created an enrolment token and configured a fresh agent through stdin. The agent enrolled using the verified private CA and appeared in the authenticated hosts API. The server container runs as a non-root user.

## External acceptance checks

| Check | Observed result |
| --- | --- |
| Real mTLS ingest, PostgreSQL sequence commit and VictoriaMetrics queries | 3,200,000 samples in 32.139 seconds: **99,567 samples/s**, with the server and load generator constrained to 4 CPUs, 32 agents and 1,000-sample batches. Tenant and host labels and committed sequences were checked. |
| Linux static agent | x86_64 musl static PIE, stripped, **10,087,744 bytes**, below the 15 MB acceptance limit. |
| SNMP v2c and v3 | Real simulator get and 64-bit interface walk passed for v2c and SHA256/AES128 v3. The final v3 test used the normal environment and the explicit worker stack, without `RUST_MIN_STACK`. |
| Nagios-compatible plugins | Unmodified Debian `monitoring-plugins-basic` 2.3.3-5+deb12u2 `check_disk` and `check_http` executed through Kestrel and produced OK checks and parsed perfdata. Package hashes were verified; an executable outside the allowlist was rejected. |
| Prometheus exposition | A running Linux agent returned non-empty `/metrics`; `promtool check metrics` passed. |
| Production UI | Seven Playwright browser tests passed against the production static bundle. Svelte check reported zero errors and warnings; production build passed; production dependency audit reported zero vulnerabilities. |
| OpenAPI | Generated document contains 52 paths and 90 unique operations. TypeScript API generation and the production build passed. |
| OpenTelemetry SDK | Official Python SDK 1.38.0 exported authenticated OTLP protobuf over verified HTTPS to the final server container. Queries returned counter 7, gauge 42, histogram count 1, sum 0.2 and bucket counts; configured `user_id` attribute dropping was verified. |
| Official OCSF schema | Fourteen synthetic records emitted by the production Rust mapping passed the official OCSF 1.1.0 validator with **zero errors and warnings**: Detection Finding create/close across five severities and API Activity CRUD. |
| Windows agent compilation | GNU Windows cross-check passed. This does not establish MSI installation or Windows service operation. |

The ingest load generator is in `crates/kestrel-server/examples/ingest_load.rs`. Reproducible SNMP acceptance is in `scripts/test-snmp.sh`, the original distribution plugin fixture is in `deploy/tests/Dockerfile.monitoring-plugins`, and the SDK demo is in `deploy/tests/otlp_sdk.py` with pinned dependencies alongside it. These checks require explicitly selected test services and Docker contexts; they are not silently run against production.

VictoriaMetrics applies a default 30-second latency offset to recent instant queries. Kestrel explicitly disables that instant-query cache policy so requested evaluation times are honoured; range-query caching remains available. Storage flushing can still delay visibility briefly, so external acceptance checks poll with a bounded deadline.

The local Rust OCSF validator intentionally checks a pinned required-field subset. Full schema acceptance was separately verified at `https://schema.ocsf.io/1.1.0/api/v2/validate` on 17 October 2026; the structured response is recorded in [the OCSF validation report](validation/ocsf-1.1.0-2026-10-17.json). To repeat it, run `cargo run -p kestrel-server --example ocsf > /tmp/kestrel-ocsf-events.json`, then `python3 deploy/tests/validate_ocsf.py /tmp/kestrel-ocsf-events.json`. This sends only synthetic exporter fixtures to the official service and requires network access. A negative test confirmed that a missing class identifier is rejected.

## Packaging and remaining release gates

Installer syntax and ShellCheck, release recipe YAML and shell syntax, WiX XML, the launchd plist, Compose configuration and Git whitespace checks passed. The recipe requires signing credentials, signs Linux agent binaries and checksums with minisign, and verifies those signatures before uploading artifacts. The macOS recipe requires Developer ID identities and a notarisation profile.

The following release checks remain unverified and must not be represented as completed:

- Actual installation and enrolment on Ubuntu, Debian and RHEL using published release artifacts.
- Actual Windows MSI installation followed by a running service and successful stop/shutdown.
- An aarch64 musl artifact build and execution on a matching runner or emulator.
- A Developer ID signed, notarised macOS package and its installation.
- Running the documented release recipe with real signing credentials and publishing release artifacts.

These are tracked by packaging issue #31. The Linux artifact and source-level service checks above are useful evidence, but do not replace these platform checks.
