DROP TRIGGER IF EXISTS workspace_maintenance_guard ON audit_outbox;
CREATE TRIGGER workspace_maintenance_guard
BEFORE INSERT OR UPDATE OR DELETE ON audit_outbox
FOR EACH ROW EXECUTE FUNCTION reject_workspace_write_during_maintenance();
