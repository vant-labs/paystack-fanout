CREATE TABLE IF NOT EXISTS sources (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL,
    allowed_ips JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS routes (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    destination_url TEXT NOT NULL,
    matcher JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeout_seconds INTEGER NOT NULL DEFAULT 10,
    max_attempts INTEGER NOT NULL DEFAULT 10,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS routes_enabled_idx ON routes (enabled, name);
CREATE INDEX IF NOT EXISTS sources_enabled_idx ON sources (enabled, name);
