BEGIN;

CREATE TABLE IF NOT EXISTS workspaces (
    id varchar(128) PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS web_users (
    id varchar(128) PRIMARY KEY,
    username varchar(255) NOT NULL UNIQUE,
    role varchar(32) NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_workspaces (
    user_id varchar(128) NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    workspace_id varchar(128) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, workspace_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id varchar(64) PRIMARY KEY,
    user_id varchar(128) NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    label varchar(255) NOT NULL,
    salt bytea NOT NULL,
    digest bytea NOT NULL,
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS web_records (
    workspace_id varchar(128) NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    collection varchar(128) NOT NULL,
    record_id varchar(128) NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, collection, record_id)
);

CREATE INDEX IF NOT EXISTS web_records_workspace_collection_idx
    ON web_records (workspace_id, collection, created_at);

COMMIT;
