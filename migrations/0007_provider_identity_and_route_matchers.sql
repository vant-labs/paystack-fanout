ALTER TABLE events ADD COLUMN IF NOT EXISTS provider_event_id TEXT NOT NULL DEFAULT '';

ALTER TABLE routes ADD COLUMN IF NOT EXISTS app_identifier TEXT;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS environment TEXT;

CREATE INDEX IF NOT EXISTS routes_provider_match_idx
    ON routes (enabled, app_identifier, environment);
