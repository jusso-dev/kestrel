-- Keep the authenticating user's home tenant while an MSP session views a grant.
ALTER TABLE sessions ADD COLUMN active_tenant_id uuid REFERENCES tenants(id);
UPDATE sessions SET active_tenant_id = tenant_id;
ALTER TABLE sessions ALTER COLUMN active_tenant_id SET NOT NULL;

ALTER TABLE problems ADD COLUMN acknowledged_by uuid;
ALTER TABLE problems ADD COLUMN acknowledgement_comment text NOT NULL DEFAULT '';

CREATE INDEX sessions_expiry_idx ON sessions(expires_at);
