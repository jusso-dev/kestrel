-- Retain the last firing value for notification context after a series disappears.
ALTER TABLE problems ADD COLUMN trigger_value text NOT NULL DEFAULT '';
