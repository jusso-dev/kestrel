CREATE INDEX agents_host_idx ON agents(tenant_id,host_id);

-- Upgrade only the shipped, previously incorrect expression.
UPDATE triggers SET expression='kestrel_load1 > 8'
WHERE expression='kestrel_cpu_load1 > 8'
AND template_id IN (SELECT id FROM templates WHERE name='Linux');

INSERT INTO items (tenant_id,template_id,key,kind,interval_s,params)
SELECT tenant_id,id,'snmp.upsBatteryStatus','snmp',30,'{"oid":"1.3.6.1.2.1.33.1.2.1.0"}'::jsonb
FROM templates WHERE name='SNMP UPS-MIB'
ON CONFLICT (tenant_id,template_id,key) DO NOTHING;
