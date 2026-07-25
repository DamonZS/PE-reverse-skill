CREATE OR REPLACE FUNCTION reject_workspace_write_during_maintenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  old_data JSONB;
  new_data JSONB;
  old_workspace TEXT;
  new_workspace TEXT;
BEGIN
  IF TG_OP <> 'INSERT' THEN old_data := to_jsonb(OLD); END IF;
  IF TG_OP <> 'DELETE' THEN new_data := to_jsonb(NEW); END IF;

  IF TG_TABLE_NAME = 'api_tokens' THEN
    IF old_data IS NOT NULL THEN SELECT workspace_id INTO old_workspace FROM users WHERE id=old_data->>'user_id'; END IF;
    IF new_data IS NOT NULL THEN SELECT workspace_id INTO new_workspace FROM users WHERE id=new_data->>'user_id'; END IF;
  ELSIF TG_TABLE_NAME = 'flow_events' THEN
    IF old_data IS NOT NULL THEN SELECT workspace_id INTO old_workspace FROM experiments WHERE id=old_data->>'experiment_id'; END IF;
    IF new_data IS NOT NULL THEN SELECT workspace_id INTO new_workspace FROM experiments WHERE id=new_data->>'experiment_id'; END IF;
  ELSIF TG_TABLE_NAME = 'workspaces' THEN
    old_workspace := old_data->>'id';
    new_workspace := new_data->>'id';
  ELSE
    old_workspace := old_data->>'workspace_id';
    new_workspace := new_data->>'workspace_id';
  END IF;

  IF EXISTS (
    SELECT 1 FROM platform_maintenance
    WHERE workspace_id IN (old_workspace,new_workspace) AND expires_at > now()
  ) THEN
    RAISE EXCEPTION 'workspace write is blocked by coordinated backup maintenance'
      USING ERRCODE='55000';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
