# ADR 0004: SvelteKit static UI embedded in the server

Status: Accepted

## Decision

The UI lives in `web/`, is built with SvelteKit `adapter-static`, and is embedded in `kestrel-server` with `rust-embed`. Charts use uPlot.

## Reasons

One binary to deploy. Svelte gives a small bundle. uPlot renders large time series quickly.
