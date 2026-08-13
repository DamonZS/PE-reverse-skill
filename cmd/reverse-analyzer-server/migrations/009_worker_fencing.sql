ALTER TABLE worker_leases
  ADD COLUMN IF NOT EXISTS fencing_token BIGINT NOT NULL DEFAULT 0;
ALTER TABLE worker_leases
  ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS worker_leases_active_idx
  ON worker_leases(experiment_id, expires_at, fencing_token);
