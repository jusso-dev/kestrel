-- Sign-in names a tenant when an address is in more than one (issue #45), so
-- an address only has to be unique inside its tenant, ignoring case.
DROP INDEX users_email_lower_key;
CREATE UNIQUE INDEX users_tenant_email_lower_key ON users (tenant_id, lower(email));
