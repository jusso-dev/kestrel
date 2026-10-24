-- Sign-in looks users up by email across tenants, so an address must name
-- exactly one user regardless of tenant or letter case.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users GROUP BY lower(email) HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'users share an email address (across tenants or by letter case); give each user a unique email before upgrading';
    END IF;
END
$$;
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- Deleting a user keeps the audit trail and removes the user's credentials.
-- SET NULL (column) needs PostgreSQL 15 or later; tenant_id stays NOT NULL.
ALTER TABLE audit_log
    DROP CONSTRAINT audit_log_user_fk,
    ADD CONSTRAINT audit_log_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (user_id);
ALTER TABLE sessions
    DROP CONSTRAINT sessions_user_fk,
    ADD CONSTRAINT sessions_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE api_tokens
    DROP CONSTRAINT api_tokens_user_fk,
    ADD CONSTRAINT api_tokens_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE user_roles
    DROP CONSTRAINT user_roles_user_fk,
    ADD CONSTRAINT user_roles_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE;
