ALTER TABLE msp_grants ADD COLUMN role text NOT NULL DEFAULT 'viewer'
CHECK (role IN ('admin','operator','viewer'));
