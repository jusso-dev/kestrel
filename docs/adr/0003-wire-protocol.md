# ADR 0003: Protobuf over HTTP/2 for agent traffic

Status: Accepted

## Decision

Agent batches are protobuf messages (`prost`), compressed with zstd, sent with `POST /api/v1/ingest` over HTTP/2. Schema lives in `crates/kestrel-proto/proto/kestrel.proto`.

## Reasons

Compact, versionable with field numbers, and easy to debug with plain HTTP tooling. gRPC was considered but adds little and complicates proxies.
