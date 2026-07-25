ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS status_code INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_event_id_unique ON audit_events(event_id);

ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT 'database-trigger';
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'system';
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS remote_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT 'succeeded';
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS status_code INTEGER NOT NULL DEFAULT 200;
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS request_id TEXT NOT NULL DEFAULT '';
UPDATE audit_outbox SET event_id='outbox-' || id WHERE event_id IS NULL;
ALTER TABLE audit_outbox ALTER COLUMN event_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS audit_outbox_event_id_unique ON audit_outbox(event_id);

CREATE OR REPLACE FUNCTION capture_workspace_mutation_outbox()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  candidate_workspace TEXT;
  candidate_resource TEXT;
  row_data JSONB;
  generated_event_id TEXT;
BEGIN
  row_data := CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  IF TG_TABLE_NAME='api_tokens' THEN
    SELECT workspace_id INTO candidate_workspace FROM users WHERE id=row_data->>'user_id';
    candidate_resource := row_data->>'id';
  ELSIF TG_TABLE_NAME='flow_events' THEN
    SELECT workspace_id INTO candidate_workspace FROM experiments WHERE id=row_data->>'experiment_id';
    candidate_resource := row_data->>'id';
  ELSE
    candidate_workspace := row_data->>'workspace_id';
    candidate_resource := COALESCE(row_data->>'id',row_data->>'provider',row_data->>'name',row_data->>'state_hash',row_data->>'code_hash',TG_TABLE_NAME);
  END IF;
  generated_event_id := md5(random()::text || clock_timestamp()::text || txid_current()::text);
  INSERT INTO audit_outbox(workspace_id,event_id,actor,role,remote_ip,action,resource_type,resource_id,outcome,status_code,details,request_id)
  VALUES(
    candidate_workspace,
    generated_event_id,
    COALESCE(NULLIF(current_setting('reverse_analyzer.actor',true),''),'database-trigger'),
    COALESCE(NULLIF(current_setting('reverse_analyzer.role',true),''),'system'),
    COALESCE(current_setting('reverse_analyzer.remote_ip',true),''),
    COALESCE(NULLIF(current_setting('reverse_analyzer.action',true),''),'database.' || lower(TG_OP)),
    TG_TABLE_NAME,
    COALESCE(candidate_resource,''),
    COALESCE(NULLIF(current_setting('reverse_analyzer.outcome',true),''),'succeeded'),
    COALESCE(NULLIF(current_setting('reverse_analyzer.status_code',true),'')::INTEGER,200),
    jsonb_build_object('operation',TG_OP),
    COALESCE(current_setting('reverse_analyzer.request_id',true),'')
  );
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
