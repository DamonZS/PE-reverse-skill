CREATE TABLE IF NOT EXISTS audit_outbox (
  id BIGSERIAL PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS audit_outbox_workspace_created_idx ON audit_outbox(workspace_id, created_at);

CREATE OR REPLACE FUNCTION capture_workspace_mutation_outbox()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  candidate_workspace TEXT;
  candidate_resource TEXT;
  row_data JSONB;
BEGIN
  row_data := CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  IF TG_TABLE_NAME = 'api_tokens' THEN
    SELECT workspace_id INTO candidate_workspace FROM users WHERE id = row_data->>'user_id';
    candidate_resource := row_data->>'id';
  ELSIF TG_TABLE_NAME = 'flow_events' THEN
    SELECT workspace_id INTO candidate_workspace FROM experiments WHERE id = row_data->>'experiment_id';
    candidate_resource := row_data->>'id';
  ELSE
    candidate_workspace := row_data->>'workspace_id';
    candidate_resource := CASE TG_TABLE_NAME
      WHEN 'users' THEN row_data->>'id'
      WHEN 'experiments' THEN row_data->>'id'
      WHEN 'knowledge_documents' THEN row_data->>'id'
      WHEN 'provider_usage' THEN row_data->>'provider'
      WHEN 'provider_configs' THEN row_data->>'name'
      WHEN 'oauth_states' THEN row_data->>'state_hash'
      WHEN 'oauth_exchange_codes' THEN row_data->>'code_hash'
      ELSE TG_TABLE_NAME
    END;
  END IF;
  INSERT INTO audit_outbox(workspace_id,action,resource_type,resource_id)
  VALUES(candidate_workspace, 'database.' || lower(TG_OP), TG_TABLE_NAME, COALESCE(candidate_resource,''));
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'users', 'api_tokens', 'experiments', 'flow_events', 'knowledge_documents',
    'provider_usage', 'provider_configs', 'oauth_states', 'oauth_exchange_codes'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS workspace_mutation_outbox ON %I', table_name);
    EXECUTE format(
      'CREATE TRIGGER workspace_mutation_outbox BEFORE INSERT OR UPDATE OR DELETE ON %I '
      'FOR EACH ROW EXECUTE FUNCTION capture_workspace_mutation_outbox()',
      table_name
    );
  END LOOP;
END;
$$;
