# ADR 0002: VictoriaMetrics for time series, PostgreSQL for config

Status: Accepted

## Options

1. Write our own embedded TSDB.
2. ClickHouse.
3. VictoriaMetrics (single node, cluster later), speaking Prometheus remote write and PromQL or MetricsQL.

## Decision

Option 3 by default, behind a `MetricStore` trait so ClickHouse can be added later.

## Reasons

- An embedded TSDB is a multi-year project on its own. Not our product.
- VictoriaMetrics single-node is one static binary, very efficient on disk, handles high cardinality well, and is Apache 2.0 licensed.
- Remote write and PromQL are open standards, so Grafana works with Kestrel data on day one.
- ClickHouse is excellent for logs and events but heavier to run for small shops.

## Consequences

Kestrel ships a `docker-compose.yml` and a systemd unit that run VictoriaMetrics alongside the server. The all-in-one package bundles it.
