-- Deleting a user removes their sign-in material and keeps the audit trail.
-- `SET NULL (user_id)` needs PostgreSQL 15 or later.
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
ALTER TABLE audit_log
    DROP CONSTRAINT audit_log_user_fk,
    ADD CONSTRAINT audit_log_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (user_id);
-- MSP grants name users of any tenant, so they have no foreign key.
DELETE FROM msp_grants g WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = g.user_id);
