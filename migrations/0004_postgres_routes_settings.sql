ALTER TABLE routes ADD COLUMN IF NOT EXISTS target_url TEXT;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS ref_prefix TEXT;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS metadata_app TEXT;

ALTER TABLE settings ADD COLUMN IF NOT EXISTS value_encrypted TEXT;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS is_secret BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id);

ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS paystack_event TEXT;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS reference TEXT;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS route_id UUID REFERENCES routes(id) ON DELETE SET NULL;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS status_code INTEGER;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS last_error TEXT;

CREATE INDEX IF NOT EXISTS routes_match_idx ON routes (enabled, ref_prefix, metadata_app);
CREATE INDEX IF NOT EXISTS deliveries_reference_idx ON deliveries (reference, created_at DESC);
