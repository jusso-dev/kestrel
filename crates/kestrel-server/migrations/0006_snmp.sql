CREATE TABLE host_snmp (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    host_id uuid NOT NULL,
    config jsonb NOT NULL,
    PRIMARY KEY (tenant_id,host_id),
    FOREIGN KEY (tenant_id,host_id) REFERENCES hosts(tenant_id,id) ON DELETE CASCADE
);
