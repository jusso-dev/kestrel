ALTER TABLE problems ADD COLUMN instance_hash text NOT NULL DEFAULT '';
ALTER TABLE problems ADD COLUMN labels jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE UNIQUE INDEX problems_one_active_instance ON problems (tenant_id, trigger_id, instance_hash) WHERE status = 'problem' AND instance_hash <> '';
CREATE UNIQUE INDEX notification_jobs_event_step ON notification_jobs
    (tenant_id, problem_id, media_type_id, (payload->>'event'), (payload->>'step'));
CREATE TABLE trigger_evaluations (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    trigger_id uuid NOT NULL,
    evaluated_at timestamptz NOT NULL,
    PRIMARY KEY(tenant_id,trigger_id),
    FOREIGN KEY(tenant_id,trigger_id) REFERENCES triggers(tenant_id,id)
);
