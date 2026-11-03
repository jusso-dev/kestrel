-- Instant queries only look back a few minutes, so the bare reachability gauge
-- vanished before for_seconds elapsed and silent hosts never alerted.
UPDATE triggers
SET expression = 'time() - max_over_time(kestrel_agent_last_seen_timestamp[24h]) > 180'
WHERE expression = 'time() - kestrel_agent_last_seen_timestamp > 180';

-- Per-host copies of template triggers record their source, so renaming or
-- deleting a template trigger reaches every copy.
ALTER TABLE triggers ADD COLUMN source_trigger_id uuid REFERENCES triggers (id) ON DELETE SET NULL;

UPDATE triggers c
SET source_trigger_id = t.id
FROM triggers t
WHERE c.tenant_id = t.tenant_id
  AND c.template_id = t.template_id
  AND c.name = t.name
  AND c.host_id IS NOT NULL
  AND c.discovered_entity_id IS NULL
  AND t.host_id IS NULL;

-- Copies whose source was already renamed or deleted. Disable rather than
-- delete so problem history keeps its trigger.
UPDATE triggers
SET enabled = false
WHERE host_id IS NOT NULL
  AND template_id IS NOT NULL
  AND discovered_entity_id IS NULL
  AND source_trigger_id IS NULL;

DROP INDEX triggers_host_template_idx;
CREATE UNIQUE INDEX triggers_host_source_idx ON triggers (tenant_id, host_id, source_trigger_id)
    WHERE source_trigger_id IS NOT NULL;
CREATE INDEX triggers_source_trigger_idx ON triggers (source_trigger_id)
    WHERE source_trigger_id IS NOT NULL;
