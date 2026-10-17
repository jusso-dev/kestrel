CREATE TABLE agent_security_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    agent_id uuid NOT NULL,
    kind text NOT NULL,
    detail jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_security_events_tenant_time_idx ON agent_security_events(tenant_id,created_at);
