-- Runtime tables for ingest, alerting, RBAC, tenancy and forwarding.
-- Every new tenant-owned table has tenant_id.

ALTER TABLE tenants ADD COLUMN parent_id uuid REFERENCES tenants (id);
ALTER TABLE tenants ADD COLUMN host_quota integer NOT NULL DEFAULT 10000;
ALTER TABLE tenants ADD COLUMN samples_per_second integer NOT NULL DEFAULT 50000;

ALTER TABLE agents ADD COLUMN last_seq bigint NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN last_seen_at timestamptz;

ALTER TABLE triggers ADD COLUMN interval_s integer NOT NULL DEFAULT 15;
ALTER TABLE triggers ADD COLUMN recover_for integer NOT NULL DEFAULT 0;
ALTER TABLE triggers ADD CONSTRAINT triggers_interval_s_min CHECK (interval_s >= 15);
ALTER TABLE triggers ADD CONSTRAINT triggers_recover_for_nonneg CHECK (recover_for >= 0);

ALTER TABLE actions ADD CONSTRAINT actions_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE notification_jobs ADD COLUMN last_error text;

ALTER TABLE maintenances ADD COLUMN host_ids jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE maintenances ADD COLUMN group_ids jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE maintenances ADD COLUMN collect_data boolean NOT NULL DEFAULT true;
ALTER TABLE maintenances ADD COLUMN suppress_problems boolean NOT NULL DEFAULT true;

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    user_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sessions_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id)
);

CREATE TABLE user_roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    user_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    host_group_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_roles_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),
    CONSTRAINT user_roles_group_fk FOREIGN KEY (tenant_id, host_group_id) REFERENCES host_groups (tenant_id, id)
);

CREATE TABLE msp_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);

CREATE TABLE check_results (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    host_id uuid NOT NULL,
    agent_id uuid,
    check_id text NOT NULL,
    state integer NOT NULL,
    output text NOT NULL DEFAULT '',
    perfdata text NOT NULL DEFAULT '',
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, host_id, check_id)
);

CREATE TABLE log_events (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    host_id uuid,
    agent_id uuid,
    source text NOT NULL,
    line text NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (created_at, id)
) PARTITION BY RANGE (created_at);

CREATE TABLE log_events_default PARTITION OF log_events DEFAULT;

CREATE TABLE problem_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    problem_id uuid NOT NULL,
    kind text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT problem_events_problem_fk FOREIGN KEY (tenant_id, problem_id) REFERENCES problems (tenant_id, id)
);

CREATE TABLE trigger_state (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    trigger_id uuid NOT NULL,
    instance_hash text NOT NULL,
    state text NOT NULL,
    since timestamptz NOT NULL,
    problem_id uuid,
    recover_since timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, trigger_id, instance_hash),
    CONSTRAINT trigger_state_trigger_fk FOREIGN KEY (tenant_id, trigger_id) REFERENCES triggers (tenant_id, id)
);

CREATE TABLE action_steps (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    action_id uuid NOT NULL,
    step integer NOT NULL CHECK (step >= 0),
    delay_s integer NOT NULL DEFAULT 0 CHECK (delay_s >= 0),
    media_type_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    user_group_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, action_id, step),
    CONSTRAINT action_steps_action_fk FOREIGN KEY (tenant_id, action_id) REFERENCES actions (tenant_id, id)
);

CREATE TABLE dashboards (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    layout jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE template_links (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    host_id uuid NOT NULL,
    template_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, host_id, template_id),
    CONSTRAINT template_links_host_fk FOREIGN KEY (tenant_id, host_id) REFERENCES hosts (tenant_id, id),
    CONSTRAINT template_links_template_fk FOREIGN KEY (tenant_id, template_id) REFERENCES templates (tenant_id, id)
);

CREATE TABLE template_parents (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    template_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, template_id, parent_id),
    CONSTRAINT template_parents_template_fk FOREIGN KEY (tenant_id, template_id) REFERENCES templates (tenant_id, id),
    CONSTRAINT template_parents_parent_fk FOREIGN KEY (tenant_id, parent_id) REFERENCES templates (tenant_id, id)
);

CREATE TABLE discovery_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    template_id uuid NOT NULL,
    name text NOT NULL,
    entity text NOT NULL,
    filter text NOT NULL DEFAULT '',
    item_prototype text NOT NULL DEFAULT '',
    trigger_prototype text NOT NULL DEFAULT '',
    keep_days integer NOT NULL DEFAULT 7 CHECK (keep_days >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    CONSTRAINT discovery_rules_template_fk FOREIGN KEY (tenant_id, template_id) REFERENCES templates (tenant_id, id)
);

CREATE TABLE discovered_entities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    host_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    entity_key text NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_seen timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, host_id, rule_id, entity_key),
    CONSTRAINT discovered_entities_host_fk FOREIGN KEY (tenant_id, host_id) REFERENCES hosts (tenant_id, id),
    CONSTRAINT discovered_entities_rule_fk FOREIGN KEY (tenant_id, rule_id) REFERENCES discovery_rules (tenant_id, id)
);

CREATE TABLE forward_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    kind text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'running', 'sent', 'failed')),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    run_after timestamptz NOT NULL DEFAULT now(),
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_tenant_id_idx ON sessions (tenant_id);
CREATE INDEX user_roles_tenant_id_idx ON user_roles (tenant_id);
CREATE INDEX msp_grants_tenant_id_idx ON msp_grants (tenant_id);
CREATE INDEX check_results_tenant_id_idx ON check_results (tenant_id);
CREATE INDEX log_events_tenant_id_idx ON log_events (tenant_id, observed_at);
CREATE INDEX problem_events_tenant_id_idx ON problem_events (tenant_id);
CREATE INDEX trigger_state_tenant_id_idx ON trigger_state (tenant_id);
CREATE INDEX action_steps_tenant_id_idx ON action_steps (tenant_id);
CREATE INDEX dashboards_tenant_id_idx ON dashboards (tenant_id);
CREATE INDEX template_links_tenant_id_idx ON template_links (tenant_id);
CREATE INDEX template_parents_tenant_id_idx ON template_parents (tenant_id);
CREATE INDEX discovery_rules_tenant_id_idx ON discovery_rules (tenant_id);
CREATE INDEX discovered_entities_tenant_id_idx ON discovered_entities (tenant_id);
CREATE INDEX forward_jobs_tenant_id_idx ON forward_jobs (tenant_id);
CREATE INDEX notification_jobs_due_idx ON notification_jobs (status, run_after);
CREATE INDEX forward_jobs_due_idx ON forward_jobs (status, run_after);

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'sessions',
        'user_roles',
        'msp_grants',
        'check_results',
        'log_events',
        'problem_events',
        'trigger_state',
        'action_steps',
        'dashboards',
        'template_links',
        'template_parents',
        'discovery_rules',
        'discovered_entities',
        'forward_jobs'
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION kestrel_set_updated_at()',
            table_name || '_set_updated_at',
            table_name
        );
    END LOOP;
END $$;
