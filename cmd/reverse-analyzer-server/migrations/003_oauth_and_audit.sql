ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS remote_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT 'unknown';

CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  redirect_uri TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS oauth_states_workspace_expiry_idx ON oauth_states(workspace_id, expires_at);

CREATE TABLE IF NOT EXISTS oauth_exchange_codes (
  code_hash TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  subject TEXT NOT NULL,
  role TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS oauth_exchange_codes_workspace_expiry_idx ON oauth_exchange_codes(workspace_id, expires_at);

CREATE TABLE IF NOT EXISTS platform_maintenance (
  workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id),
  owner TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
