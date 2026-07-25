CREATE OR REPLACE FUNCTION reject_workspace_write_during_maintenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  candidate_workspace TEXT;
  candidate_user TEXT;
  candidate_experiment TEXT;
  row_data JSONB;
BEGIN
  row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  IF TG_TABLE_NAME = 'api_tokens' THEN
    candidate_user := row_data->>'user_id';
    SELECT workspace_id INTO candidate_workspace FROM users WHERE id = candidate_user;
  ELSIF TG_TABLE_NAME = 'flow_events' THEN
    candidate_experiment := row_data->>'experiment_id';
    SELECT workspace_id INTO candidate_workspace FROM experiments WHERE id = candidate_experiment;
  ELSIF TG_TABLE_NAME = 'workspaces' THEN
    candidate_workspace := row_data->>'id';
  ELSE
    candidate_workspace := row_data->>'workspace_id';
  END IF;

  IF candidate_workspace IS NOT NULL AND EXISTS (
    SELECT 1 FROM platform_maintenance
    WHERE workspace_id = candidate_workspace AND expires_at > now()
  ) THEN
    RAISE EXCEPTION 'workspace % is in coordinated backup maintenance', candidate_workspace
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'workspaces', 'users', 'api_tokens', 'experiments', 'flow_events',
    'knowledge_documents', 'provider_usage', 'provider_configs', 'worker_leases',
    'audit_events', 'oauth_states', 'oauth_exchange_codes'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS workspace_maintenance_guard ON %I', table_name);
    EXECUTE format(
      'CREATE TRIGGER workspace_maintenance_guard BEFORE INSERT OR UPDATE OR DELETE ON %I '
      'FOR EACH ROW EXECUTE FUNCTION reject_workspace_write_during_maintenance()',
      table_name
    );
  END LOOP;
END;
$$;
