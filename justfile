compose := "docker compose -f deploy/dev/docker-compose.yml"

# Start PostgreSQL 16, VictoriaMetrics and Mailpit.
dev-up:
    {{compose}} up -d

# Stop the dev stack.
dev-down:
    {{compose}} down

# Run the server against deploy/dev/server.toml.
server:
    cargo run -p kestrel-server -- --config deploy/dev/server.toml

# Run the agent against deploy/dev/agent.toml.
agent:
    cargo run -p kestrel-agent -- --config deploy/dev/agent.toml
