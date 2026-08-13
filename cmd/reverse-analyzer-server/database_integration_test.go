package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPostgreSQLConcurrentEventSequence(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	id := newID()
	x := Experiment{ID: id, Status: "queued", CreatedAt: now(), UpdatedAt: now()}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	var outboxCount int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_outbox WHERE workspace_id=$1 AND resource_type='experiments' AND resource_id=$2`, root, id).Scan(&outboxCount); err != nil || outboxCount != 1 {
		t.Fatalf("transactional audit outbox count=%d err=%v", outboxCount, err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id=$1 AND workspace_id=$2`, id, root)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	const count = 24
	var wg sync.WaitGroup
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.appendEvent(id, "concurrent", "running", "event", nil)
		}()
	}
	wg.Wait()
	events, err := s.events(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != count {
		t.Fatalf("events=%d want=%d", len(events), count)
	}
	for index, event := range events {
		if event.Sequence != int64(index+1) {
			t.Fatalf("event[%d].sequence=%d", index, event.Sequence)
		}
	}
	current, err := s.loadExperiment(id)
	if err != nil || current.Orchestration == nil || current.Orchestration.LastEventSequence != count {
		t.Fatalf("concurrent event projection mismatch: %#v err=%v", current.Orchestration, err)
	}
}

func TestPostgreSQLWorkspaceIsolationAndRestartRecovery(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	left, leftRoot := testServer(t, "integration-admin")
	right, rightRoot := testServer(t, "integration-admin")
	defer left.close()
	defer right.close()
	id := newID()
	x := Experiment{ID: id, Status: "running", CreatedAt: now(), UpdatedAt: now(), Reconstruction: ReconstructionState{BuildPassed: true, BehaviorPassed: true, CompleteBuildable: true}}
	if err := left.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = left.db.Exec(`DELETE FROM api_tokens WHERE user_id IN (SELECT id FROM users WHERE workspace_id IN ($1,$2))`, leftRoot, rightRoot)
		_, _ = left.db.Exec(`DELETE FROM users WHERE workspace_id IN ($1,$2)`, leftRoot, rightRoot)
		_, _ = left.db.Exec(`DELETE FROM experiments WHERE id=$1`, id)
		_, _ = left.db.Exec(`DELETE FROM workspaces WHERE id IN ($1,$2)`, leftRoot, rightRoot)
	}()
	if err := right.saveExperiment(x); err == nil {
		t.Fatal("another workspace overwrote a guessed experiment id")
	}
	if _, err := right.loadExperiment(id); err == nil {
		t.Fatal("another workspace loaded a guessed experiment id")
	}
	if response := request(t, right, http.MethodGet, "/api/experiments/"+id+"/events", "integration-admin", nil); response.Code == http.StatusOK {
		t.Fatalf("another workspace read guessed events: %s", response.Body.String())
	}
	created := request(t, left, http.MethodPost, "/api/auth/tokens", "integration-admin", map[string]any{"Subject": "left-viewer", "Role": "viewer"})
	var token map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &token)
	if response := request(t, right, http.MethodGet, "/api/workspace", token["token"].(string), nil); response.Code != http.StatusForbidden {
		t.Fatalf("cross-workspace token status=%d body=%s", response.Code, response.Body.String())
	}
	restarted := newServer(left.cfg)
	defer restarted.close()
	recovered, err := restarted.loadExperiment(id)
	if err != nil || recovered.Status != "failed" || recovered.Reconstruction.BuildPassed || recovered.Reconstruction.BehaviorPassed || recovered.Reconstruction.CompleteBuildable {
		t.Fatalf("restart recovery did not revoke unprovable gates: %#v err=%v", recovered, err)
	}
	var migrationCount int
	if err := restarted.db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&migrationCount); err != nil || migrationCount != 9 {
		t.Fatalf("migration ledger count=%d err=%v", migrationCount, err)
	}
}

func TestPostgreSQLWorkerEventsRequireCurrentFencingToken(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	id := newID()
	x := Experiment{ID: id, Status: "running", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{"worker_fencing_token": float64(2)}}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	if _, err := s.db.Exec(`INSERT INTO worker_leases(experiment_id,workspace_id,owner_id,heartbeat_at,expires_at,fencing_token,version) VALUES($1,$2,$3,now(),now()+interval '30 seconds',2,2)`, id, root, s.workerOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.appendWorkerEvent(id, "progress", "running", "stale", nil, 1); err == nil {
		t.Fatal("stale fencing token appended a worker event")
	}
	if err := s.appendWorkerEvent(id, "progress", "running", "current", nil, 2); err != nil {
		t.Fatal(err)
	}
	events, err := s.events(id)
	if err != nil || len(events) != 1 || events[0].Message != "current" {
		t.Fatalf("worker events=%#v err=%v", events, err)
	}
	current, err := s.loadExperiment(id)
	if err != nil || current.Orchestration == nil || current.Orchestration.LastEventSequence != events[0].Sequence {
		t.Fatalf("worker event projection not persisted: %#v err=%v", current.Orchestration, err)
	}
}

func TestPostgreSQLExpiredLeaseCannotHeartbeatOrAppendEvents(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	id := newID()
	x := Experiment{ID: id, Status: "running", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{"worker_fencing_token": float64(3)}}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	if _, err := s.db.Exec(`INSERT INTO worker_leases(experiment_id,workspace_id,owner_id,heartbeat_at,expires_at,fencing_token,version) VALUES($1,$2,$3,now()-interval '1 minute',now()-interval '1 second',3,1)`, id, root, s.workerOwner); err != nil {
		t.Fatal(err)
	}
	result, err := s.db.Exec(`UPDATE worker_leases SET heartbeat_at=now(),expires_at=now()+interval '30 seconds',version=version+1 WHERE experiment_id=$1 AND workspace_id=$2 AND owner_id=$3 AND fencing_token=$4 AND expires_at>now()`, id, root, s.workerOwner, 3)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := result.RowsAffected(); rows != 0 {
		t.Fatal("expired lease was revived")
	}
	if err := s.appendWorkerEvent(id, "progress", "running", "late", nil, 3); err == nil {
		t.Fatal("expired lease appended a worker event")
	}
}

func TestPostgreSQLRecoverySkipsActiveLeaseAndRecoversExpiredLease(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	activeID := newID()
	expiredID := newID()
	for _, id := range []string{activeID, expiredID} {
		if err := s.saveExperiment(Experiment{ID: id, Status: "running", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{}}); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM worker_leases WHERE experiment_id IN ($1,$2)`, activeID, expiredID)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id IN ($1,$2)`, activeID, expiredID)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	if _, err := s.db.Exec(`INSERT INTO worker_leases(experiment_id,workspace_id,owner_id,heartbeat_at,expires_at,fencing_token,version) VALUES($1,$2,'active-owner',now(),now()+interval '30 seconds',1,1),($3,$2,'expired-owner',now()-interval '1 minute',now()-interval '1 second',1,1)`, activeID, root, expiredID); err != nil {
		t.Fatal(err)
	}
	s.recoverInterruptedExperiments()
	active, err := s.loadExperiment(activeID)
	if err != nil || active.Status != "running" {
		t.Fatalf("active lease was recovered: %#v err=%v", active, err)
	}
	expired, err := s.loadExperiment(expiredID)
	if err != nil || expired.Status != "failed" || expired.Orchestration == nil || expired.Orchestration.LastEventSequence != 1 {
		t.Fatalf("expired lease was not recovered atomically: %#v err=%v", expired, err)
	}
}

func TestPostgreSQLCancellationDeletesLeaseAndRejectsLateWorkerEvent(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	id := newID()
	x := Experiment{ID: id, Status: "running", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{"worker_fencing_token": float64(4)}}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	if _, err := s.db.Exec(`INSERT INTO worker_leases(experiment_id,workspace_id,owner_id,heartbeat_at,expires_at,fencing_token,version) VALUES($1,$2,$3,now(),now()+interval '30 seconds',4,1)`, id, root, s.workerOwner); err != nil {
		t.Fatal(err)
	}
	cancelled, err := s.cancel(id)
	if err != nil || cancelled.Status != "cancelled" {
		t.Fatalf("cancel failed: %#v err=%v", cancelled, err)
	}
	var leaseCount int
	if err := s.db.QueryRow(`SELECT count(*) FROM worker_leases WHERE experiment_id=$1`, id).Scan(&leaseCount); err != nil || leaseCount != 0 {
		t.Fatalf("lease count=%d err=%v", leaseCount, err)
	}
	if err := s.appendWorkerEvent(id, "progress", "running", "late", nil, 4); err == nil {
		t.Fatal("late worker event was accepted after cancellation")
	}
	current, err := s.loadExperiment(id)
	if err != nil || current.Status != "cancelled" || current.Orchestration == nil || current.Orchestration.LastEventSequence != 1 {
		t.Fatalf("cancelled state or projection mismatch: %#v err=%v", current, err)
	}
}

func TestPostgreSQLMaintenanceLockRejectsTransactionStartedBeforeFreeze(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	id := newID()
	x := Experiment{ID: id, Status: "queued", CreatedAt: now(), UpdatedAt: now()}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM platform_maintenance WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	txDB, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer txDB.Rollback()
	if _, err = s.db.Exec(`INSERT INTO platform_maintenance(workspace_id,owner,expires_at) VALUES($1,'integration-freeze',now()+interval '1 minute')`, root); err != nil {
		t.Fatal(err)
	}
	if _, err = txDB.Exec(`UPDATE experiments SET status='running' WHERE id=$1 AND workspace_id=$2`, id, root); err == nil {
		t.Fatal("transaction that started before maintenance freeze committed a workspace write")
	}
}

func TestPostgreSQLMaintenanceRejectsCrossWorkspaceMoveWhenEitherSideFrozen(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, left := testServer(t, "integration-admin")
	defer s.close()
	right := left + "-move-target"
	id := newID()
	if _, err := s.db.Exec(`INSERT INTO workspaces(id,name) VALUES($1,'move-target')`, right); err != nil {
		t.Fatal(err)
	}
	if err := s.saveExperiment(Experiment{ID: id, Status: "queued", CreatedAt: now(), UpdatedAt: now()}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM platform_maintenance WHERE workspace_id IN ($1,$2)`, left, right)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE id=$1`, id)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id IN ($1,$2)`, left, right)
	}()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = s.db.Exec(`INSERT INTO platform_maintenance(workspace_id,owner,expires_at) VALUES($1,'move-freeze',now()+interval '1 minute')`, right); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE experiments SET workspace_id=$1 WHERE id=$2 AND workspace_id=$3`, right, id, left); err == nil {
		t.Fatal("cross-workspace move entered a frozen destination")
	}
}

func TestPostgreSQLAuditOutboxReplaysAfterRestartWithCompleteIdentity(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	eventID := "restart-" + newID()
	if _, err := s.db.Exec(`INSERT INTO audit_outbox(workspace_id,event_id,actor,role,remote_ip,action,resource_type,resource_id,outcome,status_code,details,request_id) VALUES($1,$2,'operator','admin','203.0.113.7','experiment.cancel','experiment','fixture','succeeded',200,'{"source":"test"}','request-42')`, root, eventID); err != nil {
		t.Fatal(err)
	}
	s.close()
	restarted := newServer(s.cfg)
	defer restarted.close()
	defer func() {
		_, _ = restarted.db.Exec(`DELETE FROM audit_events WHERE event_id=$1`, eventID)
		_, _ = restarted.db.Exec(`DELETE FROM audit_outbox WHERE event_id=$1`, eventID)
		_, _ = restarted.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	var actor, role, remoteIP, requestID string
	var delivered bool
	if err := restarted.db.QueryRow(`SELECT e.actor,e.role,e.remote_ip,e.details->>'request_id',o.delivered_at IS NOT NULL FROM audit_events e JOIN audit_outbox o ON o.event_id=e.event_id WHERE e.event_id=$1`, eventID).Scan(&actor, &role, &remoteIP, &requestID, &delivered); err != nil {
		t.Fatal(err)
	}
	if actor != "operator" || role != "admin" || remoteIP != "203.0.113.7" || requestID != "request-42" || !delivered {
		t.Fatalf("replayed identity actor=%q role=%q ip=%q request=%q delivered=%v", actor, role, remoteIP, requestID, delivered)
	}
	if err := restarted.deliverAuditOutbox(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := restarted.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event_id=$1`, eventID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("idempotent event count=%d err=%v", count, err)
	}
}

func TestPostgreSQLAuditOutboxDeliveryIsRejectedDuringMaintenance(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	defer s.close()
	eventID := "frozen-delivery-" + newID()
	if _, err := s.db.Exec(`INSERT INTO audit_outbox(workspace_id,event_id,actor,role,action,resource_type,resource_id) VALUES($1,$2,'operator','admin','fixture','fixture','frozen')`, root, eventID); err != nil {
		t.Fatal(err)
	}
	// Pre-create the idempotent destination row so delivery reaches the guarded
	// audit_outbox UPDATE instead of being rejected by audit_events first.
	if _, err := s.db.Exec(`INSERT INTO audit_events(event_id,workspace_id,actor,role,remote_ip,action,resource_type,resource_id,outcome,status_code,details) VALUES($1,$2,'operator','admin','','fixture','fixture','frozen','succeeded',200,'{}')`, eventID, root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO platform_maintenance(workspace_id,owner,expires_at) VALUES($1,'audit-freeze',now()+interval '1 minute')`, root); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM platform_maintenance WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM audit_events WHERE event_id=$1`, eventID)
		_, _ = s.db.Exec(`DELETE FROM audit_outbox WHERE event_id=$1`, eventID)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
	}()
	if err := s.deliverAuditOutbox(); err == nil {
		t.Fatal("audit outbox delivery updated delivered_at during maintenance")
	}
	var delivered bool
	if err := s.db.QueryRow(`SELECT delivered_at IS NOT NULL FROM audit_outbox WHERE event_id=$1`, eventID).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered {
		t.Fatal("guarded audit outbox row was marked delivered")
	}
}

func TestPostgreSQLOAuthStateIsWorkspaceBoundAndRestartSafe(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	left, leftRoot := testServer(t, "integration-admin")
	right, rightRoot := testServer(t, "integration-admin")
	defer left.close()
	defer right.close()
	defer func() {
		_, _ = left.db.Exec(`DELETE FROM oauth_states WHERE workspace_id IN ($1,$2)`, leftRoot, rightRoot)
		_, _ = left.db.Exec(`DELETE FROM workspaces WHERE id IN ($1,$2)`, leftRoot, rightRoot)
	}()
	state := "postgres-restart-state"
	redirect := "https://console.example/callback"
	if err := left.storeOAuthState(state, redirect, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := right.consumeOAuthState(state, redirect, time.Now()); err == nil {
		t.Fatal("another workspace consumed OAuth state")
	}
	restarted := newServer(left.cfg)
	defer restarted.close()
	if err := restarted.consumeOAuthState(state, redirect, time.Now()); err != nil {
		t.Fatalf("restart could not consume state: %v", err)
	}
	if err := left.consumeOAuthState(state, redirect, time.Now()); err == nil {
		t.Fatal("another instance consumed OAuth state twice")
	}
}

func TestPostgreSQLKnowledgeLifecycle(t *testing.T) {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") == "" {
		t.Skip("set REVERSE_ANALYZER_DATABASE_URL to run PostgreSQL integration tests")
	}
	s, root := testServer(t, "integration-admin")
	if s.dbErr != nil {
		t.Fatal(s.dbErr)
	}
	if s.db == nil {
		t.Fatal("PostgreSQL was not initialized")
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(`DELETE FROM api_tokens WHERE user_id IN (SELECT id FROM users WHERE workspace_id=$1)`, root)
		_, _ = s.db.Exec(`DELETE FROM users WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM knowledge_documents WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM provider_configs WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM provider_usage WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM experiments WHERE workspace_id=$1`, root)
		_, _ = s.db.Exec(`DELETE FROM workspaces WHERE id=$1`, root)
		s.close()
	})

	created := request(t, s, http.MethodPost, "/api/knowledge", "integration-admin", map[string]any{"title": "PostgreSQL", "content": "integration"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var doc map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &doc)
	id := doc["id"].(string)

	updated := request(t, s, http.MethodPatch, "/api/knowledge/"+id, "integration-admin", map[string]any{"tags": []string{"database", "live"}})
	if updated.Code != http.StatusOK {
		t.Fatal(updated.Body.String())
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM knowledge_documents WHERE id=$1 AND workspace_id=$2 AND payload->'tags' ? 'live'`, id, root).Scan(&count); err != nil || count != 1 {
		t.Fatalf("database document not persisted: count=%d err=%v", count, err)
	}
	if deleted := request(t, s, http.MethodDelete, "/api/knowledge/"+id, "integration-admin", nil); deleted.Code != http.StatusNoContent {
		t.Fatal(deleted.Code, deleted.Body.String())
	}

	provider := request(t, s, http.MethodPut, "/api/providers", "integration-admin", map[string]any{
		"name": "database_provider", "kind": "openai-compatible", "model": "db-model", "base_url": "https://provider.invalid/v1", "api_key_env": "DATABASE_PROVIDER_KEY", "enabled": true, "priority": 20,
	})
	if provider.Code != http.StatusOK {
		t.Fatal(provider.Body.String())
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM provider_configs WHERE workspace_id=$1 AND name='database_provider'`, root).Scan(&count); err != nil || count != 1 {
		t.Fatalf("provider config not persisted: count=%d err=%v", count, err)
	}

	createdToken := request(t, s, http.MethodPost, "/api/auth/tokens", "integration-admin", map[string]any{"Subject": "db-viewer", "Role": "viewer"})
	if createdToken.Code != http.StatusCreated {
		t.Fatal(createdToken.Body.String())
	}
	var tokenPayload map[string]any
	_ = json.Unmarshal(createdToken.Body.Bytes(), &tokenPayload)
	tokenID := tokenPayload["id"].(string)
	issuedToken := tokenPayload["token"].(string)
	if read := request(t, s, http.MethodGet, "/api/workspace", issuedToken, nil); read.Code != http.StatusOK {
		t.Fatal(read.Code, read.Body.String())
	}
	if revoked := request(t, s, http.MethodDelete, "/api/auth/tokens/"+tokenID, "integration-admin", nil); revoked.Code != http.StatusNoContent {
		t.Fatal(revoked.Code, revoked.Body.String())
	}
	if denied := request(t, s, http.MethodGet, "/api/workspace", issuedToken, nil); denied.Code != http.StatusUnauthorized {
		t.Fatal(denied.Code, denied.Body.String())
	}
}
