# Operations

## Notifications

Channels are email (SMTP STARTTLS), Slack incoming webhooks, Teams Workflows adaptive cards, generic webhooks and PagerDuty. Secrets are encrypted with age. The identity file is `data_dir/secret.key` and is mode 0600 on Unix.

A webhook body is signed with HMAC-SHA256. The header is `X-Kestrel-Signature: sha256=<hex>`.

Example, secret `docs-example-secret`, body `{"hello":"kestrel"}`:

```text
sha256=3edb78dd97c282d06b0f563a20febacec404e7dc935309850197a003d2b20344
```

Jobs are claimed with `FOR UPDATE SKIP LOCKED`, retried up to 10 times, and record `last_error`. Tests use fakes. They do not send to Slack, Teams, PagerDuty or a public SMTP server.

## Escalation and maintenance

An action has steps with a delay. A later step is skipped once the problem is acknowledged or resolved. Maintenance windows can be a single interval or a weekly RRULE evaluated in the window's timezone, so a local time survives a daylight-saving change. `suppress_problems` stops new problems. Notification suppression is separate and is checked before a job is queued.

## Forwarding

SIEM delivery is outbound only, to URLs an operator saved. Syslog uses TLS and RFC 5425 octet-counted frames. See [integrations/wedgetail.md](integrations/wedgetail.md).

## Tenants

Every tenant-owned query includes `tenant_id`. An MSP user sees another tenant only after an explicit grant. Ingest is limited per tenant; the limit responds with 429.

## Roles

See [rbac.md](rbac.md).
