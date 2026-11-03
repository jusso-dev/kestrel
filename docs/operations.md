# Operations

## Notifications

Channels are email (SMTP STARTTLS), Slack incoming webhooks, Teams Workflows adaptive cards, generic webhooks and PagerDuty. Secrets are encrypted with age. The identity file is `data_dir/secret.key` and is mode 0600 on Unix.

A webhook body is signed with HMAC-SHA256. The header is `X-Kestrel-Signature: sha256=<hex>`.

Media configuration may set `subject_template` and `body_template` (or `template` for the body), interpolating MiniJinja variables `problem.id`, `problem.name`, `problem.status`, `host`, `trigger`, `value` and `url`, for example `{{ problem.name }} on {{ host }}`. Expressions, function/filter calls and control-flow statements are rejected. The default templates apply when omitted. Template size, recursion, execution fuel and streamed output are bounded; invalid templates fail delivery and follow the normal retry policy.

Example, secret `docs-example-secret`, body `{"hello":"kestrel"}`:

```text
sha256=3edb78dd97c282d06b0f563a20febacec404e7dc935309850197a003d2b20344
```

Jobs are claimed with `FOR UPDATE SKIP LOCKED`, retried up to 10 times, and record `last_error`. Tests use fakes. They do not send to Slack, Teams, PagerDuty or a public SMTP server.

## Escalation and maintenance

An action has steps with a delay. A later step is skipped once the problem is acknowledged or resolved. Maintenance windows can be a single interval or a weekly RRULE evaluated in the window's timezone, so a local time survives a daylight-saving change. `suppress_problems` stops new problems. Notification suppression is checked again before delivery; due jobs remain pending and are deferred until the maintenance window ends.

## Forwarding

SIEM delivery is outbound only, to URLs an operator saved. Syslog uses TLS and RFC 5425 octet-counted frames. See [integrations/wedgetail.md](integrations/wedgetail.md).

## Outbound requests

Server-side HTTP checks, Prometheus scrapes, webhook, Slack, Teams and PagerDuty media, media tests and SIEM webhooks fetch URLs that tenant administrators supply. Before connecting, the server resolves the host and refuses loopback, link-local (including cloud metadata such as `169.254.169.254`), unspecified, multicast and broadcast addresses, IPv4-mapped forms of these, the configured `victoria_url` host and port, and the server's own listen addresses when they are bound to a specific IP. The check applies to the address actually connected, so DNS rebinding does not bypass it. Private ranges (RFC 1918 and IPv6 ULA) remain allowed. Redirects are not followed and proxy environment variables are ignored for these requests.

To let these requests reach loopback, for example an exporter on the server host itself, set `allow_loopback_targets = true` (or `KESTREL_ALLOW_LOOPBACK_TARGETS=true`). The metric store stays refused either way. Leave it off on multi-tenant servers.

An email media that names its own `smtp_host` or `smtp_port` does not inherit the server's SMTP username and password.

## Tenants

Every tenant-owned query includes `tenant_id`. An MSP user sees another tenant only after an explicit grant. Ingest is limited per tenant; the limit responds with 429. An owner grants a user of their tenant a role in a direct child tenant with `POST /api/v1/msp/grants`, lists those grants with `GET /api/v1/msp/grants`, and revokes one with `DELETE /api/v1/msp/grants` and `{"user_id","tenant_id"}`, which also ends that user's sessions in the tenant.

Email addresses are unique within a tenant, ignoring letter case, and sign-in matches them case-insensitively. The same address can have an account in more than one tenant. Sign-in then needs a tenant: `POST /api/v1/login` takes an optional `tenant` (name or id). Without one, a correct password returns 409 with the tenants it matched, and the UI asks the user to pick; a wrong password is a plain 401. An email in one tenant signs in as before. Without a tenant, the password is checked against each account that has the email (at most ten), so response time can hint that an address is in several tenants; it never reveals whether a single-tenant address exists. Naming the tenant avoids this.

## Sign-in protection

Failed sign-ins are counted per account from each source address (email, case-insensitive, plus the client address) and per source address (IPv4 address or IPv6 /64). Keying the account counter on the source means nobody can lock another user out from elsewhere; the source limit bounds password spraying across accounts. An attempt counts before the password is checked and is taken back when it succeeds or the server fails before judging it, so parallel guesses cannot overrun a limit and successful sign-ins from a shared NAT never lock it out. Once either limit is reached, sign-in for that key returns 429 with `Retry-After` until the window that began with its first failure ends (at most one day). Unknown emails are counted the same way, so a 429 does not reveal whether an account exists. Counters are kept in memory per server process. At most four Argon2 verifications run at once. Behind a reverse proxy that is not listed in `trusted_proxies`, every client shares the proxy's address.

```toml
# Defaults.
[login]
max_failures_per_account = 10
max_failures_per_source = 50
failure_window_secs = 900
```

Behind a reverse proxy, list the proxy addresses so the client address is read from `X-Forwarded-For` (the right-most address that is not a trusted proxy). The header is ignored from any other peer.

```toml
trusted_proxies = ["10.0.0.5"]
```

Every refused password is audited as `session.login_failed` in the tenant of each account it was tried against, with the attempted email and source address and never the password. An attempt naming a tenant that has no such email is audited in that tenant. An unknown email with no tenant has no tenant to own the record and is only written to the server log. Successful sign-ins are audited as `session.login` with the source address. Both are forwarded to configured SIEM targets with `src_endpoint.ip`.

## Users

Deleting a user ends their sessions and API tokens and removes their MSP grants. Their audit entries stay, with the user link cleared. This needs PostgreSQL 15 or later.

## Health

`GET /healthz` answers 200 while the process serves requests. `GET /readyz` answers 200 when PostgreSQL responds within two seconds and 503 otherwise. Neither needs authentication or returns detail. The server stops on SIGTERM or Ctrl-C, finishes in-flight requests and drains queued metric writes before exiting.

Agent enrolment does not take over an existing host of the same name if the host has an active agent or sits outside the token's host group; enrolment then responds with 409. Revoke the old agent first.

## Roles

See [rbac.md](rbac.md).

## Backup and restore

Back up PostgreSQL, the VictoriaMetrics storage directory and the server data directory together. PostgreSQL holds configuration, accounts, sessions, trigger states, problems and delivery queues. VictoriaMetrics holds time series. The server directory holds the internal CA, server certificate, enrolment directory and `secret.key`, which decrypts notification and SIEM target credentials. Losing this key makes those saved credentials unusable.

Use `pg_dump --format=custom` with credentials supplied through your database client's protected configuration. Store the dump and an encrypted archive of the server directory in restricted backup storage. Stop writes or use filesystem snapshots for a consistent backup; stop VictoriaMetrics before copying its data or use its supported snapshot API. Never paste private keys into a terminal transcript, issue or support request.

Restore into an isolated environment first, using the same application version. Restore the database with `pg_restore`, the metrics data into VictoriaMetrics, and the complete server directory with its original ownership and restrictive permissions. Start the server and verify login, an existing agent's authenticated ingest, historical queries and notification job state. A successful backup is one that has passed this restore check.

## Upgrade

Take and verify a backup before replacing binaries or images. Preserve the server and agent data directories; agents must keep their identity and offline buffer. Review migration and release notes, stop the server, install the new version, then start it. PostgreSQL migrations run automatically. Migration 0011 requires PostgreSQL 15 or later and stops with an error if two users share an email address (across tenants or by letter case); rename those users before upgrading. Rebuild the web bundle before a source server build (`cd web && npm ci && npm run build`). The container build performs this step itself.

Do not start an older binary against a migrated database unless its release explicitly supports that schema. To roll back an incompatible migration, stop the new server and restore the matching application, database and data-directory backup. Notification and SIEM delivery are at least once: a crash after remote acceptance but before transaction commit may redeliver a job. Receivers should deduplicate by problem or event identifier.

## Packaging and verification

The [release recipe](../.github/workflows/release.yml) builds both Linux musl architectures, checks static linkage and the 15 MB agent limit, builds the Windows MSI, signs the macOS agent and installer, notarises and staples the package, and packages the server as deb, rpm and a distroless container. macOS signing requires a configured runner keychain with Developer ID Application and Installer identities plus a notarytool profile. Native server packages built on Ubuntu 22.04 require glibc 2.35 or later; use the container on older distributions. See [validation](VALIDATION.md) for checks actually executed; a recipe is not evidence that platform installation passed.

Linux releases require the GitHub Actions secret `RELEASE_MINISIGN_SECRET_KEY`, containing the complete dedicated, unencrypted minisign secret-key file. Prepare that key outside CI with `minisign -G -W`, store its contents directly through GitHub's secret settings, and keep the original protected; never commit it or put its contents in logs or command arguments. The signing step writes it to an owner-only temporary file outside the artifact directory, removes the environment variable before invoking minisign, and deletes the file when the step exits. Missing or invalid signing configuration fails the job.

Each Linux artifact bundle includes the agent, `SHA256SUMS`, both corresponding `.minisig` signatures, and the derived `minisign.pub`; the job verifies both signatures before upload. Distribute the public key through a separately trusted channel and compare it with the bundled public key before trusting a release. A public key downloaded alongside an untrusted binary does not establish its authenticity.

The Linux installer accepts `--token`, `--server`, `--url` and `--sha256` (or their documented `KESTREL_*` environment variables). Supply `--ca-file` for an internal server CA. For signature verification, supply **both** `--signature-url` and `--minisign-pub` naming a trusted public key file; a missing signature or invalid signature fails installation. SHA-256 verification is always required. The installer refuses to overwrite an existing agent configuration and enables its hardened systemd service after installation; `--no-start` defers startup.
