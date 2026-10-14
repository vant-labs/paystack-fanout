ALTER TABLE events ADD COLUMN IF NOT EXISTS normalized_body BYTEA;

CREATE TABLE IF NOT EXISTS store_purchases (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL,
    purchase_key TEXT NOT NULL,
    original_transaction_id TEXT,
    purchase_token TEXT,
    account_id TEXT,
    product_id TEXT NOT NULL,
    licence TEXT NOT NULL,
    app_identifier TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('production', 'sandbox')),
    status TEXT NOT NULL CHECK (status IN ('active', 'grace', 'expired', 'refunded', 'revoked')),
    expires_at TIMESTAMPTZ,
    last_event_id TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (provider, purchase_key)
);

CREATE INDEX IF NOT EXISTS store_purchases_account_idx
    ON store_purchases (account_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS store_purchases_original_transaction_idx
    ON store_purchases (provider, original_transaction_id);

CREATE TABLE IF NOT EXISTS entitlement_audit (
    id BIGSERIAL PRIMARY KEY,
    provider TEXT NOT NULL,
    purchase_key TEXT NOT NULL,
    account_id TEXT,
    event_id TEXT,
    action TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS entitlement_audit_purchase_idx
    ON entitlement_audit (provider, purchase_key, created_at DESC);
