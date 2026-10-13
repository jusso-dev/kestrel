-- Core config and state. Every tenant-owned row carries tenant_id.
-- The tenants table is the root, so it has no tenant_id of its own.

CREATE FUNCTION kestrel_set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE host_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    email text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    host_group_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, email),
    FOREIGN KEY (tenant_id, host_group_id) REFERENCES host_groups (tenant_id, id)
);

CREATE TABLE api_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    user_id uuid NOT NULL,
    CONSTRAINT api_tokens_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),
    name text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    host_group_id uuid,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    FOREIGN KEY (tenant_id, host_group_id) REFERENCES host_groups (tenant_id, id)
);

CREATE TABLE agents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    host_id uuid,
    CONSTRAINT agents_host_fk FOREIGN KEY (tenant_id, host_id) REFERENCES hosts (tenant_id, id),
    hostname text NOT NULL,
    os text NOT NULL DEFAULT '',
    arch text NOT NULL DEFAULT '',
    cert_serial text NOT NULL DEFAULT '',
    cert_not_after timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE templates (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    template_id uuid NOT NULL,
    CONSTRAINT items_template_fk FOREIGN KEY (tenant_id, template_id) REFERENCES templates (tenant_id, id),
    key text NOT NULL,
    kind text NOT NULL,
    interval_s integer NOT NULL CHECK (interval_s > 0),
    params jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, template_id, key)
);

CREATE TABLE triggers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    template_id uuid,
    host_id uuid,
    CONSTRAINT triggers_template_fk FOREIGN KEY (tenant_id, template_id) REFERENCES templates (tenant_id, id),
    CONSTRAINT triggers_host_fk FOREIGN KEY (tenant_id, host_id) REFERENCES hosts (tenant_id, id),
    name text NOT NULL,
    expression text NOT NULL,
    severity text NOT NULL,
    for_seconds integer NOT NULL DEFAULT 0 CHECK (for_seconds >= 0),
    recovery_expr text,
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE problems (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    trigger_id uuid NOT NULL,
    host_id uuid,
    CONSTRAINT problems_trigger_fk FOREIGN KEY (tenant_id, trigger_id) REFERENCES triggers (tenant_id, id),
    CONSTRAINT problems_host_fk FOREIGN KEY (tenant_id, host_id) REFERENCES hosts (tenant_id, id),
    status text NOT NULL CHECK (status IN ('ok', 'pending', 'problem', 'resolved')),
    severity text NOT NULL,
    opened_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    acknowledged_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE media_types (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    kind text NOT NULL,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE actions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    media_type_id uuid,
    CONSTRAINT actions_media_type_fk FOREIGN KEY (tenant_id, media_type_id) REFERENCES media_types (tenant_id, id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE notification_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    problem_id uuid,
    media_type_id uuid NOT NULL,
    CONSTRAINT notification_jobs_problem_fk FOREIGN KEY (tenant_id, problem_id) REFERENCES problems (tenant_id, id),
    CONSTRAINT notification_jobs_media_type_fk FOREIGN KEY (tenant_id, media_type_id) REFERENCES media_types (tenant_id, id),
    status text NOT NULL CHECK (status IN ('pending', 'running', 'sent', 'failed')),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    run_after timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE maintenances (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    host_group_id uuid,
    starts_at timestamptz NOT NULL,
    CONSTRAINT maintenances_host_group_fk FOREIGN KEY (tenant_id, host_group_id) REFERENCES host_groups (tenant_id, id),
    ends_at timestamptz NOT NULL,
    rrule text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    user_id uuid,
    CONSTRAINT audit_log_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),
    action text NOT NULL,
    target text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX host_groups_tenant_id_idx ON host_groups (tenant_id);
CREATE INDEX users_tenant_id_idx ON users (tenant_id);
CREATE INDEX api_tokens_tenant_id_idx ON api_tokens (tenant_id);
CREATE INDEX hosts_tenant_id_idx ON hosts (tenant_id);
CREATE INDEX agents_tenant_id_idx ON agents (tenant_id);
CREATE INDEX templates_tenant_id_idx ON templates (tenant_id);
CREATE INDEX items_tenant_id_idx ON items (tenant_id);
CREATE INDEX triggers_tenant_id_idx ON triggers (tenant_id);
CREATE INDEX problems_tenant_id_idx ON problems (tenant_id);
CREATE INDEX media_types_tenant_id_idx ON media_types (tenant_id);
CREATE INDEX actions_tenant_id_idx ON actions (tenant_id);
CREATE INDEX notification_jobs_tenant_id_idx ON notification_jobs (tenant_id);
CREATE INDEX maintenances_tenant_id_idx ON maintenances (tenant_id);
CREATE INDEX audit_log_tenant_id_idx ON audit_log (tenant_id);

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'tenants',
        'host_groups',
        'users',
        'api_tokens',
        'hosts',
        'agents',
        'templates',
        'items',
        'triggers',
        'problems',
        'media_types',
        'actions',
        'notification_jobs',
        'maintenances',
        'audit_log'
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION kestrel_set_updated_at()',
            table_name || '_set_updated_at',
            table_name
        );
    END LOOP;
END $$;

-- Same id the enrolment file store uses until those rows move here.
INSERT INTO tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'default');
