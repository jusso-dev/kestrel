# Validation

Commands run on this machine while finishing issues 15–32:

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings` — no issues
- `cargo test --workspace -- --test-threads=8` — 113 passed, 1 ignored, 0 failed
- `npm run build` in `web/` — SvelteKit adapter-static wrote `web/build`

`cargo test` does not run `cargo bench`. The ignored test is `snmp_walks_snmpsim`.

## Not executed

These checks need hardware or tools that were not available when the code was written. No numbers below were invented.

| Check | Why it was not run |
| --- | --- |
| 50,000 samples/s ingest on a 4 vCPU host | No 4 vCPU benchmark host was provisioned. `cargo bench -p kestrel-server --bench ingest` decodes a 1,000-sample batch locally. That is not the throughput acceptance test. |
| `cross` musl agent builds and Windows MSI (`cargo wix`) | Release builds are described in `docs/ci/release.yml`. They were not executed on Linux, Windows and macOS from this machine. |
| snmpsim walk | `snmp_walks_snmpsim` is `#[ignore]`. Start the `snmp` compose profile before running it. |
| `promtool check metrics` | The agent checks the exposition text in-process (`validate_exposition`). `promtool` was not required for the unit tests. |
| Playwright browser run | `web/tests` describes the UI paths. A browser install was not required for `cargo test`. |

## Present in libraries, not in the long-running loops

- The HTTP API catalogue is in memory. Postgres repositories and built-in template seeding run on startup. API login, hosts, sessions and problems are not read back from Postgres after a restart. `kestrel-server admin create` inserts a database user that the memory catalogue does not load.
- The trigger evaluator, notification job claim, and SIEM forwarder are library functions with tests. `kestrel-server` does not spawn those loops.
- The agent ships built-in collectors. Config polling, plugin execution and the localhost Prometheus listener are gated in `desired` and are not called from `serve`.
- Syslog forwarding in tests is TCP with RFC 5425 octet counting. TLS syslog is not implemented.
- Ingest sequence checks are in memory. `agents.last_seq` is not updated in Postgres.

## Security notes from the tests

- Passwords are argon2id. Tests reject the wrong password and do not put it in the response body.
- Webhook signatures use HMAC-SHA256. The documented vector is in the notify tests.
- Notification and SIEM tests use in-process fakes or a local mock server.
