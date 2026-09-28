CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    raw_body BYTEA NOT NULL,
    content_type TEXT NOT NULL,
    signature TEXT NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    dedupe_key TEXT NOT NULL,
    matched_route TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'retrying', 'delivered', 'dead', 'unrouted')),
    received_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    UNIQUE (source, dedupe_key)
);

CREATE INDEX IF NOT EXISTS events_received_at_idx ON events (received_at DESC);
CREATE INDEX IF NOT EXISTS events_filter_idx ON events (status, matched_route, event_type, received_at DESC);

CREATE TABLE IF NOT EXISTS deliveries (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    destination_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivering', 'retrying', 'delivered', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    locked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS deliveries_queue_idx ON deliveries (status, next_attempt_at);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id BIGSERIAL PRIMARY KEY,
    delivery_id UUID NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
    attempt INTEGER NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    status_code INTEGER,
    latency_ms INTEGER NOT NULL,
    response_body TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS delivery_attempts_delivery_idx ON delivery_attempts (delivery_id, attempt);

