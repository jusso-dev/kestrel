# Quick start

Prerequisites: Git, Docker with Compose, and a checked-out copy of this repository. The source-built agent example also needs the current stable Rust toolchain; the per-platform agent packages provide an alternative. Run every command from the repository root. Choose your Docker context explicitly; this example uses a local engine. An initial source build can take several minutes.

```sh
export KESTREL_DOCKER_CONTEXT=default
docker --context "$KESTREL_DOCKER_CONTEXT" compose -p kestrel-dev -f deploy/dev/docker-compose.yml --profile server up --build -d
```

This starts PostgreSQL 16, VictoriaMetrics, Mailpit and the HTTPS server with its embedded UI. The server waits for the database health check and applies migrations. The default database credentials are for development only. The UI is bound to loopback on port 8443; keep this stack private.

Create the first administrator without putting the password in command arguments or shell history. The following prompt uses Bash:

```sh
read -rsp 'Administrator password (at least 8 characters): ' KESTREL_ADMIN_PASSWORD
echo
export KESTREL_ADMIN_PASSWORD
docker --context "$KESTREL_DOCKER_CONTEXT" compose -p kestrel-dev -f deploy/dev/docker-compose.yml exec -e KESTREL_ADMIN_PASSWORD server /kestrel-server admin create --email ops@example.com --config /etc/kestrel/server.toml
unset KESTREL_ADMIN_PASSWORD
```

The server creates its internal CA and a certificate for `localhost`. Copy the **public CA certificate** to your workstation and trust it in your browser's certificate store before opening <https://localhost:8443>. For CLI checks, pass the certificate with `curl --cacert`; keep verification enabled.

```sh
docker --context "$KESTREL_DOCKER_CONTEXT" compose -p kestrel-dev -f deploy/dev/docker-compose.yml cp server:/var/lib/kestrel/ca.crt ./kestrel-dev-ca.crt
curl --cacert ./kestrel-dev-ca.crt https://localhost:8443/
```

Sign in as `ops@example.com`. Create a one-time enrolment token on the server, saving it directly into a private file:

```sh
umask 077
docker --context "$KESTREL_DOCKER_CONTEXT" compose -p kestrel-dev -f deploy/dev/docker-compose.yml exec -T server /kestrel token create --ttl 1h --data-dir /var/lib/kestrel > ./kestrel-enrol-token
```

Install an agent using the [per-platform instructions](agent.md). For a source-built agent on this workstation:

```sh
cargo build -p kestrel-agent
./target/debug/kestrel-agent --configure --server https://localhost:8443 --config ./agent-local.toml --data-dir ./data/agent-local --ca-file ./kestrel-dev-ca.crt --token-stdin < ./kestrel-enrol-token
./target/debug/kestrel-agent --config ./agent-local.toml
```

Distribute the CA certificate through a trusted channel when using another host. Set `public_url` to the actual server DNS name **before** the first start so the generated certificate names match. Regenerate or supply a suitable server certificate when changing that name. Never distribute `ca.key`, `server.key` or `secret.key` to agents.

The host appears after enrolment and the first batch. The Linux template supplies built-in checks; [templates](agent.md#config-the-server-sends) can add items. View graphs in Hosts and live problem changes in Problems. Mailpit is available at <http://localhost:8025> for local SMTP tests. [Triggers](triggers.md) explains alert expressions and [operations](operations.md) covers backup and upgrade.

Stop your development stack without deleting its volumes:

```sh
docker --context "$KESTREL_DOCKER_CONTEXT" compose -p kestrel-dev -f deploy/dev/docker-compose.yml --profile server down
```

For a remote Docker context, Compose bind mounts resolve on the daemon host. Copy the deployment configuration there, or use a matching remote checkout. Use an SSH tunnel for the loopback HTTPS endpoint rather than exposing the development stack publicly.
