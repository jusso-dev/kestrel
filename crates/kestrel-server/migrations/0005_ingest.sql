ALTER TABLE items ALTER COLUMN template_id DROP NOT NULL;
ALTER TABLE items ADD COLUMN host_id uuid;
ALTER TABLE items ADD COLUMN discovered_entity_id uuid REFERENCES discovered_entities(id) ON DELETE CASCADE;
ALTER TABLE items ADD CONSTRAINT items_host_fk FOREIGN KEY (tenant_id,host_id) REFERENCES hosts(tenant_id,id);
CREATE UNIQUE INDEX items_host_key_idx ON items(tenant_id,host_id,key);
ALTER TABLE triggers ADD COLUMN discovered_entity_id uuid REFERENCES discovered_entities(id) ON DELETE SET NULL;
ALTER TABLE triggers ADD COLUMN enabled boolean NOT NULL DEFAULT true;
CREATE UNIQUE INDEX triggers_discovery_idx ON triggers(tenant_id,host_id,discovered_entity_id,name) WHERE discovered_entity_id IS NOT NULL;
CREATE UNIQUE INDEX triggers_host_template_idx ON triggers(tenant_id,host_id,template_id,name) WHERE host_id IS NOT NULL AND template_id IS NOT NULL;
