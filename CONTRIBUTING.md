# Contributing

Thanks for looking at Kestrel. Issues and pull requests are welcome on GitHub.

## Build

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The UI lives in `web/`. `npm run build` writes `web/build`, which the server embeds. `npm run gen:api` refreshes the TypeScript client from the OpenAPI document.

## Tests

Use fakes for HTTP notifications, SIEM forwarding and metrics. Do not point a test at the public internet. Do not commit secrets, tokens or `data_dir/secret.key`.

PostgreSQL tests run when `DATABASE_URL` points at PostgreSQL 16. Without it, those tests skip.

## Style

Match the surrounding module. Australian English in docs. Keep tenant filters on every tenant-owned query.
