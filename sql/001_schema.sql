CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    secret_encrypted BYTEA,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_timestep BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_logs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    username TEXT,
    source TEXT NOT NULL,
    result TEXT NOT NULL,
    reason TEXT NOT NULL,
    radius_client TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_logs_created_at ON auth_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_auth_logs_username ON auth_logs (username);
