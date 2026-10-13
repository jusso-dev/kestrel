# ADR 0005: PromQL-based trigger expressions

Status: Accepted

## Decision

Triggers are PromQL expressions evaluated against the metric store, plus Kestrel fields (`for`, `severity`, `recovery_expr`, `labels`). Zabbix-style simple triggers in the UI compile down to PromQL.

## Reasons

Avoid inventing a language. Users already know PromQL, and the UI hides it for simple cases.
