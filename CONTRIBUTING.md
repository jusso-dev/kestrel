# Contributing

Thanks for looking at Kestrel. Issues and pull requests are welcome on GitHub.

## Build

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit
```

The minimum supported Rust version is the workspace `rust-version` (1.89). Raise it, and the `msrv` job in `.github/workflows/ci.yml`, when a dependency needs a newer compiler. `cargo audit` ignores are listed with their reasons in `.cargo/audit.toml`.

The UI lives in `web/`. Run `npm ci`, `npm audit --audit-level=high`, `npm run check`, `npm run build` and `npm test` there. Install Playwright's Chromium browser with `npx playwright install chromium` before the browser tests. `npm test` builds and serves the production bundle for its browser checks. `npm run build` writes `web/build`, which the server embeds. Commit `web/build` with any change to `web/`: CI rebuilds it and fails if the committed copy differs.

CI (`.github/workflows/ci.yml`) runs these checks on Linux, macOS and Windows for every pull request and push to `main`, plus the PostgreSQL tests against a `postgres:16` service. `release.yml` only runs when started by hand. From the repository root, export the OpenAPI document with `cargo run -q -p kestrel-server --example openapi --no-default-features > crates/kestrel-server/openapi.json`, then run `npm run gen:api` in `web/` to refresh the generated TypeScript client types.

## Tests

Use fakes for HTTP notifications, SIEM forwarding and metrics. Do not point a test at the public internet. Do not commit secrets, tokens or `data_dir/secret.key`.

PostgreSQL tests run when `DATABASE_URL` points at PostgreSQL 16. Without it, those tests skip.

For isolated SNMP v2c and v3 authPriv acceptance, set `DOCKER_CONTEXT` to your intended Docker engine and `SNMPSIM_BIND_ADDR` to its reachable simulator address, then run `scripts/test-snmp.sh`. The script creates a temporary simulator and credentials, invokes the external tests and removes its own resources. Never reuse production device credentials in fixtures.

To check the unchanged distribution `check_disk` and `check_http` binaries through Kestrel's command runner, build and run the isolated Debian fixture. Choose the Docker context explicitly; the container uses only a local HTTP fixture and needs no network access at runtime:

```sh
docker --context "$DOCKER_CONTEXT" build -f deploy/tests/Dockerfile.monitoring-plugins -t kestrel-monitoring-plugins-test .
docker --context "$DOCKER_CONTEXT" run --rm --network none kestrel-monitoring-plugins-test
```

## Style

Match the surrounding module. Australian English in docs. Keep tenant filters on every tenant-owned query.
