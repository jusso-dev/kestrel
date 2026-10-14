# Quick start

This starts the local stack from `deploy/dev/docker-compose.yml` and a server container. The database password in that file is the development default. Do not reuse it in production.

```sh
cd deploy/dev
docker compose up -d postgres victoria mailpit
```

Build and run the server against that stack:

```sh
docker build -f Dockerfile.server -t kestrel-server .
docker run --rm -p 8443:8443 --network host \
  -e KESTREL_DATABASE_URL=postgres://kestrel:kestrel@127.0.0.1:5432/kestrel \
  -e KESTREL_VICTORIA_URL=http://127.0.0.1:8428 \
  -e KESTREL_LISTEN=0.0.0.0:8443 \
  kestrel-server
```

Create the first user. The password is read from the environment so it is not stored in the shell history if you export it only for the command:

```sh
KESTREL_ADMIN_PASSWORD='choose-a-long-password' \
  kestrel-server admin create --email ops@example.com --config deploy/dev/server.toml
```

Open the UI at the server URL and sign in. Enrol an agent with `kestrel token create` and the steps in [agent.md](agent.md).

Mailpit listens on port 8025 for messages the server sends to the development SMTP port 1025. The unit tests do not send mail.
