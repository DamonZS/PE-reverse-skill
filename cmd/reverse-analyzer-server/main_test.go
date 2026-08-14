package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func testServer(t *testing.T, token string) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	front := filepath.Join(root, "frontend")
	if err := os.MkdirAll(front, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(front, "index.html"), []byte("<html>go</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	server := newServer(Config{Workspace: root, Frontend: front, Addr: "127.0.0.1:0", Token: token, Python: "python", Timeout: time.Second})
	t.Cleanup(server.close)
	return server, root
}
func request(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestHealthAndAuth(t *testing.T) {
	s, _ := testServer(t, "secret")
	if w := request(t, s, "GET", "/api/health", "", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(t, s, "GET", "/api/workspace", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(t, s, "GET", "/api/workspace", "secret", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}

func TestLivenessAndReadinessAreSeparate(t *testing.T) {
	s, _ := testServer(t, "secret")
	s.dbErr = fmt.Errorf("database unavailable")
	if w := request(t, s, "GET", "/healthz", "", nil); w.Code != http.StatusOK {
		t.Fatalf("liveness must survive a dependency outage: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, s, "GET", "/readyz", "", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness must fail during a dependency outage: %d %s", w.Code, w.Body.String())
	}
}

func TestDatabaseOutageReturnsServiceUnavailable(t *testing.T) {
	s, _ := testServer(t, "secret")
	s.dbErr = fmt.Errorf("database unavailable")
	response := request(t, s, http.MethodGet, "/api/experiments", "secret", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("database outage status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCORSAllowsSameOriginModuleRequests(t *testing.T) {
	s, _ := testServer(t, "")
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8090/assets/index.js", nil)
	request.Host = "127.0.0.1:8090"
	request.Header.Set("Origin", "http://127.0.0.1:8090")
	request.Header.Set("Sec-Fetch-Dest", "script")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code == http.StatusForbidden {
		t.Fatalf("same-origin module request was blocked: %s", response.Body.String())
	}
}

func TestCORSUsesExplicitAllowlist(t *testing.T) {
	s, _ := testServer(t, "secret")
	s.cfg.AllowedOrigins = map[string]bool{"https://console.example": true}
	allowed := httptest.NewRequest(http.MethodOptions, "/api/workspace", nil)
	allowed.Header.Set("Origin", "https://console.example")
	allowed.Header.Set("Access-Control-Request-Method", http.MethodGet)
	allowedResponse := httptest.NewRecorder()
	s.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusNoContent || allowedResponse.Header().Get("Access-Control-Allow-Origin") != "https://console.example" {
		t.Fatalf("allowed preflight failed: %d %#v", allowedResponse.Code, allowedResponse.Header())
	}
	denied := httptest.NewRequest(http.MethodGet, "/api/workspace", nil)
	denied.Header.Set("Origin", "https://attacker.example")
	deniedResponse := httptest.NewRecorder()
	s.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden || deniedResponse.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin was accepted: %d %#v", deniedResponse.Code, deniedResponse.Header())
	}
}

func TestForwardedClientIPRequiresTrustedProxy(t *testing.T) {
	s, _ := testServer(t, "secret")
	s.cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "10.2.3.4:5123"
	trusted.Header.Set("X-Forwarded-For", "203.0.113.9, 10.2.3.4")
	if got := s.clientIP(trusted); got != "203.0.113.9" {
		t.Fatalf("trusted proxy client IP=%q", got)
	}
	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "192.0.2.8:5123"
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := s.clientIP(untrusted); got != "192.0.2.8" {
		t.Fatalf("untrusted proxy spoofed client IP=%q", got)
	}
}

func TestHTTPServerHasBoundedConnectionTimeouts(t *testing.T) {
	s, _ := testServer(t, "secret")
	server := newHTTPServer(s.cfg, s)
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes <= 0 {
		t.Fatalf("HTTP server limits are incomplete: %#v", server)
	}
	if server.MaxHeaderBytes > 1<<20 {
		t.Fatalf("HTTP headers are too large: %d", server.MaxHeaderBytes)
	}
}

func TestStaticFrontendPreventsStaleBundleWhiteScreen(t *testing.T) {
	s, _ := testServer(t, "")
	assets := filepath.Join(s.cfg.Frontend, "assets")
	if err := os.MkdirAll(assets, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "index-current.js"), []byte("console.log('ready')"), 0600); err != nil {
		t.Fatal(err)
	}

	index := request(t, s, http.MethodGet, "/", "", nil)
	if index.Code != http.StatusOK || index.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("index cache policy=%d %#v", index.Code, index.Header())
	}
	asset := request(t, s, http.MethodGet, "/assets/index-current.js", "", nil)
	if asset.Code != http.StatusOK || !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset cache policy=%d %#v", asset.Code, asset.Header())
	}
	missing := request(t, s, http.MethodGet, "/assets/index-stale.js", "", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("stale asset must be 404, got %d %s", missing.Code, missing.Body.String())
	}
	if strings.Contains(missing.Body.String(), "<html>go</html>") {
		t.Fatal("stale asset incorrectly fell back to index.html")
	}
}
func TestCreateFlowRequiresWorkspaceTarget(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	w := request(t, s, "POST", "/api/experiments", "", map[string]any{"target": "sample.bin", "mode": "evidence-first"})
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var p map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	x := p["experiment"].(map[string]any)
	if x["status"] != "queued" {
		t.Fatal(x)
	}
	id := x["id"].(string)
	events := request(t, s, "GET", "/api/experiments/"+id+"/events", "", nil)
	if events.Code != 200 {
		t.Fatal(events.Body.String())
	}
}

func TestEventEndpointsRejectUnknownExperiment(t *testing.T) {
	s, _ := testServer(t, "")
	id := strings.Repeat("f", 32)
	response := request(t, s, http.MethodGet, "/api/experiments/"+id+"/events", "", nil)
	if response.Code == http.StatusOK {
		t.Fatalf("unknown experiment events leaked as success: %s", response.Body.String())
	}
}

func TestCatalogAssetRoutesIntoRealAnalysisArguments(t *testing.T) {
	s, root := testServer(t, "")
	_ = os.WriteFile(filepath.Join(root, "sample.exe"), []byte("MZ"), 0600)
	w := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{
		"target": "sample.exe", "mode": "evidence-first", "requested_asset": "ghidra_decompile",
	})
	if w.Code != http.StatusCreated {
		t.Fatal(w.Body.String())
	}
	var payload map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &payload)
	raw, _ := json.Marshal(payload["experiment"])
	var experiment Experiment
	_ = json.Unmarshal(raw, &experiment)
	args := analysisArgs(experiment, filepath.Join(root, "out"))
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--decompile") || !strings.Contains(joined, "--reconstruct") {
		t.Fatalf("catalog asset was not routed into analysis args: %v", args)
	}
	if experiment.Metadata["requested_asset"] != "ghidra_decompile" {
		t.Fatalf("missing requested asset audit metadata: %#v", experiment.Metadata)
	}
}

func TestSourceEditableIncludesReconstructedMobileAndWebSources(t *testing.T) {
	for _, path := range []string{"MainActivity.java", "MainActivity.kt", "classes.smali", "AndroidManifest.xml", "index.html", "app.js", "theme.css"} {
		if !sourceEditable(path) {
			t.Fatalf("expected reconstructed source to be editable: %s", path)
		}
	}
}

func TestArtifactSummaryReportsArchivedWorkerLogSize(t *testing.T) {
	s, root := testServer(t, "")
	analysis := filepath.Join(root, "experiments", "legacy", "analysis")
	if err := os.MkdirAll(filepath.Join(analysis, "package"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(analysis, "worker-output.json"), []byte("worker log"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(analysis, "package", "sample.bin"), []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}

	summary := s.artifactSummary(analysis)
	if summary["log_bytes"] != int64(len("worker log")) {
		t.Fatalf("expected archived worker log size, got %#v", summary)
	}
}

func TestFailedExperimentExposesArchivedWorkerDiagnostics(t *testing.T) {
	s, root := testServer(t, "")
	id := newID()
	x := Experiment{Schema: 1, SchemaVersion: 1, ID: id, Sample: "sample.exe", Status: "failed", CreatedAt: now(), UpdatedAt: now(), Options: map[string]any{}, Metadata: map[string]any{}, Error: "exit status 2"}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	analysis := filepath.Join(root, "experiments", id, "analysis")
	if err := os.MkdirAll(analysis, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(analysis, "worker-output.json"), []byte("tool bootstrap failed: missing dependency\n"), 0600); err != nil {
		t.Fatal(err)
	}

	response := request(t, s, http.MethodGet, "/api/experiments/"+id, "", nil)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var payload Experiment
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error != "tool bootstrap failed: missing dependency" {
		t.Fatalf("diagnostics not exposed: %#v", payload)
	}
	if len(payload.Artifacts) != 1 || !strings.Contains(fmt.Sprint(payload.Artifacts[0]["path"]), "worker-output.json") {
		t.Fatalf("failed task artifacts missing: %#v", payload.Artifacts)
	}
}

func TestReconstructionCompletionRequiresEveryHardGate(t *testing.T) {
	state := reconstructionState(ReconstructionState{
		AnalysisComplete: true,
		SourceGenerated:  true,
		BuildPassed:      true,
	})
	if state.CompleteBuildable {
		t.Fatal("build success alone must not mark reconstruction complete")
	}
	if state.Stage != "behavior_validation_pending" {
		t.Fatalf("unexpected stage after build: %#v", state)
	}
	if !containsString(state.BlockingReasons, "behavior_validation_not_passed") {
		t.Fatalf("missing behavior validation gate: %#v", state)
	}

	state.BehaviorPassed = true
	state.StructureComplete = true
	state.DependenciesLocked = true
	state = reconstructionState(state)
	if !state.CompleteBuildable || state.Stage != "complete_buildable" || len(state.BlockingReasons) != 0 {
		t.Fatalf("all hard gates should complete reconstruction: %#v", state)
	}
}

func TestLegacyExperimentDerivesReconstructionGatesFromArtifactsAndEvents(t *testing.T) {
	s, root := testServer(t, "")
	id := "11111111111111111111111111111111"
	project := filepath.Join(root, "experiments", id, "analysis", "reconstructed_fixture")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "CMakeLists.txt"), []byte("project(legacy)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	x := Experiment{ID: id, Sample: filepath.Join(root, "legacy.exe"), Status: "completed", Options: map[string]any{"reconstruct": true}}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	s.appendEvent(id, "build_completed", "completed", "legacy build passed", nil)

	response := request(t, s, http.MethodGet, "/api/experiments/"+id, "", nil)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var payload Experiment
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Reconstruction.AnalysisComplete || !payload.Reconstruction.SourceGenerated || !payload.Reconstruction.BuildPassed {
		t.Fatalf("legacy evidence was not migrated: %#v", payload.Reconstruction)
	}
	if payload.Reconstruction.CompleteBuildable || payload.Reconstruction.Stage != "behavior_validation_pending" {
		t.Fatalf("legacy task bypassed hard gates: %#v", payload.Reconstruction)
	}
}

func TestLoadModelReconstructionSummarizesCallsAndUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reconstructed", "docs")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"status": "executed", "provider": "openai_compatible", "model": "fixture-model",
		"calls":                []any{map[string]any{"module_id": "app"}, map[string]any{"module_id": "helper"}},
		"usage":                map[string]any{"input_tokens": 21, "output_tokens": 8, "total_tokens": 29},
		"applied_change_count": 2,
	}
	if err := writeFileJSON(filepath.Join(path, "model-reconstruction.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadModelReconstruction(root)
	if !ok || state["call_count"] != 2 || state["input_tokens"] != float64(21) || state["output_tokens"] != float64(8) || state["applied_change_count"] != float64(2) {
		t.Fatalf("unexpected model reconstruction summary: %#v", state)
	}
	if !strings.Contains(fmt.Sprint(state["artifact"]), "model-reconstruction.json") {
		t.Fatalf("missing model artifact path: %#v", state)
	}
}

func TestLoadBuildReadinessRequiresExplicitBooleans(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reconstructed", "docs")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"structure_complete": true, "dependencies_locked": false, "target_count": 2, "dependency_count": 1, "blocking_reasons": []string{"floating_dependency:x"}}
	if err := writeFileJSON(filepath.Join(path, "build-readiness.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBuildReadiness(root)
	if !ok || state["structure_complete"] != true || state["dependencies_locked"] != false || state["target_count"] != float64(2) {
		t.Fatalf("unexpected build readiness: %#v", state)
	}
}

func TestLoadRepairLoopSummaryFailsClosedAndExposesTrustedRounds(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "archive-workspace-v3", "project", "docs")
	if err := os.MkdirAll(filepath.Join(docs, "build-repair", "iteration-01"), 0755); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"schema_version": 1, "status": "exhausted", "iterations_completed": 1,
		"blocking_reasons": []any{"repair_iteration_budget_exhausted"},
		"usage":            map[string]any{"input_tokens": 12, "output_tokens": 5, "total_tokens": 17},
		"iterations": []any{map[string]any{
			"iteration": 1, "status": "failed", "diagnostic_bytes": 42,
			"diagnostics":  "docs/build-repair/iteration-01/diagnostics.log",
			"build_before": "docs/build-repair/iteration-01/build-before.json",
			"build_after":  "docs/build-repair/iteration-01/build-after.json",
			"repair":       "docs/build-repair/iteration-01/repair.json",
		}},
	}
	for _, name := range []string{"diagnostics.log", "build-before.json", "build-after.json", "repair.json"} {
		if err := os.WriteFile(filepath.Join(docs, "build-repair", "iteration-01", name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeFileJSON(filepath.Join(docs, "build-repair-loop.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadRepairLoopSummary(root, "build")
	if !ok || state["status"] != "exhausted" || state["iterations_completed"] != int64(1) {
		t.Fatalf("unexpected summary: %#v", state)
	}
	rounds := state["iterations"].([]map[string]any)
	if len(rounds) != 1 || rounds[0]["diagnostics"] != "archive-workspace-v3/project/docs/build-repair/iteration-01/diagnostics.log" {
		t.Fatalf("untrusted round artifacts: %#v", rounds)
	}
	payload["iterations_completed"] = 2
	if err := writeFileJSON(filepath.Join(docs, "build-repair-loop.json"), payload); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadRepairLoopSummary(root, "build"); ok {
		t.Fatalf("iteration count mismatch must fail closed: %#v", state)
	}
	payload["iterations_completed"] = 1
	payload["iterations"] = []any{map[string]any{"iteration": 2, "status": "failed"}}
	if err := writeFileJSON(filepath.Join(docs, "build-repair-loop.json"), payload); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadRepairLoopSummary(root, "build"); ok {
		t.Fatalf("non-contiguous iteration must fail closed: %#v", state)
	}

	payload["iterations"] = []any{map[string]any{"iteration": 1, "status": "failed", "diagnostics": "../../outside.log"}}
	if err := writeFileJSON(filepath.Join(docs, "build-repair-loop.json"), payload); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadRepairLoopSummary(root, "build"); ok {
		t.Fatalf("escaping artifact must fail closed: %#v", state)
	}
	if err := os.WriteFile(filepath.Join(docs, "build-repair-loop.json"), []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadRepairLoopSummary(root, "build"); ok {
		t.Fatalf("malformed artifact must fail closed: %#v", state)
	}
}

func TestBehaviorValidationArtifactSizeLimitFailsClosed(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "project", "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "behavior-validation.json"), make([]byte, maxArtifactPreviewBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadBehaviorValidationResult(root); ok {
		t.Fatalf("oversized behavior result must fail closed: %#v", state)
	}
}

func TestArtifactPreviewLimitsJSONAndRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	s := newServer(Config{Workspace: root, Frontend: root, Addr: "127.0.0.1:0", Python: "python", Timeout: time.Second})
	id := strings.Repeat("a", 32)
	if err := s.saveExperiment(Experiment{ID: id, Status: "completed", CreatedAt: now(), UpdatedAt: now()}); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "experiments", id, "analysis", "report.json")
	if err := os.MkdirAll(filepath.Dir(inside), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	preview := request(t, s, http.MethodGet, "/api/artifacts?preview=1&path=experiments/"+id+"/analysis/report.json", "", nil)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"preview"`) {
		t.Fatalf("preview failed: %d %s", preview.Code, preview.Body.String())
	}
	if err := os.WriteFile(inside, make([]byte, maxArtifactPreviewBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	large := request(t, s, http.MethodGet, "/api/artifacts?preview=1&path=experiments/"+id+"/analysis/report.json", "", nil)
	if large.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large preview must be rejected: %d", large.Code)
	}
	escape := request(t, s, http.MethodGet, "/api/artifacts?preview=1&path=../outside.json", "", nil)
	if escape.Code == http.StatusOK {
		t.Fatalf("path traversal preview must fail")
	}
}

func TestArtifactRequiresOwnedExperimentPath(t *testing.T) {
	s, root := testServer(t, "")
	path := filepath.Join(root, "reports", "unowned.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"secret":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, http.MethodGet, "/api/artifacts?preview=1&path=reports/unowned.json", "", nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unowned artifact status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestExecutionConfirmationPersistsBeforeStartWithLocalActor(t *testing.T) {
	s, root := testServer(t, "")
	x := Experiment{Schema: 1, SchemaVersion: 1, ID: newID(), Sample: "sample.bin", Status: "queued", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{}, Options: map[string]any{}, Reconstruction: reconstructionState(ReconstructionState{})}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/experiments/"+x.ID+"/execute", nil)
	if _, err := s.startConfirmed(x.ID, r); err != nil {
		t.Fatal(err)
	}
	stored, err := s.loadExperiment(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	audit, ok := stored.Metadata["execution_confirmation"].(map[string]any)
	if !ok || audit["actor"] != "local-anonymous" || audit["role"] != "local" || audit["timestamp"] == "" {
		t.Fatalf("confirmation audit missing: %#v", audit)
	}
	events, err := s.events(x.ID)
	if err != nil || len(events) < 2 || events[0].Type != "execution_confirmed" || events[1].Type != "started" {
		t.Fatalf("confirmation event must precede worker: %#v %v", events, err)
	}
	if _, err = os.Stat(filepath.Join(root, "experiments", x.ID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentExecuteClaimsOnceAndPreservesConfirmationActor(t *testing.T) {
	s, _ := testServer(t, "")
	x := Experiment{Schema: 1, SchemaVersion: 1, ID: newID(), Sample: "sample.bin", Status: "queued", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{}, Options: map[string]any{}, Reconstruction: reconstructionState(ReconstructionState{})}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := s.startConfirmed(x.ID, httptest.NewRequest(http.MethodPost, "/api/experiments/"+x.ID+"/execute", nil))
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("exactly one concurrent execute must succeed, got %d", successes)
	}
	stored, err := s.loadExperiment(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	audit, _ := stored.Metadata["execution_confirmation"].(map[string]any)
	if stored.Status != "running" || audit["actor"] != "local-anonymous" || audit["role"] != "local" {
		t.Fatalf("unexpected claimed experiment: %#v", stored)
	}
	events, err := s.events(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	confirmations := 0
	for _, event := range events {
		if event.Type == "execution_confirmed" {
			confirmations++
		}
	}
	if confirmations != 1 {
		t.Fatalf("confirmation must be written once: %#v", events)
	}
}

func TestRetryAllowsOnlyCompletedRepairGateOrExhaustion(t *testing.T) {
	s, _ := testServer(t, "")
	base := Experiment{Schema: 1, SchemaVersion: 1, Sample: "sample.bin", Status: "completed", CreatedAt: now(), UpdatedAt: now(), Options: map[string]any{}, Reconstruction: reconstructionState(ReconstructionState{})}
	for _, tc := range []struct {
		name, status string
		allowed      bool
	}{{"ordinary", "passed", false}, {"failed", "failed", true}, {"gated", "dependency-gated", true}, {"exhausted", "exhausted", true}} {
		t.Run(tc.name, func(t *testing.T) {
			x := base
			x.ID = newID()
			x.Metadata = map[string]any{"build_repair_loop": map[string]any{"status": tc.status}}
			if err := s.saveExperiment(x); err != nil {
				t.Fatal(err)
			}
			retried, err := s.retry(x.ID)
			if tc.allowed && (err != nil || retried.Status != "queued" || retried.Metadata["retry_of"] != x.ID) {
				t.Fatalf("expected whole-flow retry: %#v %v", retried, err)
			}
			if !tc.allowed && err == nil {
				t.Fatalf("ordinary completed task must not retry: %#v", retried)
			}
		})
	}
}

func TestLoadAutomatedBuildResultRejectsUnisolatedPass(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "project", "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(docs, "build-result.json")
	if err := writeFileJSON(path, map[string]any{"schema_version": 1, "status": "passed", "build_passed": true, "isolated": false, "stages": []any{map[string]any{"name": "configure", "status": "passed", "return_code": 0}, map[string]any{"name": "build", "status": "passed", "return_code": 0}}, "artifact_count": 0, "artifacts": []any{}}); err != nil {
		t.Fatal(err)
	}
	state, ok := loadAutomatedBuildResult(root)
	if ok {
		t.Fatalf("unisolated build must not pass: %#v", state)
	}
	artifactContent := []byte("fixture")
	artifactPath := filepath.Join(root, "project", "build", "fixture.exe")
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, artifactContent, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifactContent)
	validPayload := func() map[string]any {
		return map[string]any{"schema_version": 1, "status": "passed", "build_passed": true, "isolated": true, "stages": []any{map[string]any{"name": "configure", "status": "passed", "return_code": 0}, map[string]any{"name": "build", "status": "passed", "return_code": 0}}, "artifact_count": 1, "artifacts": []any{map[string]any{"path": "build/fixture.exe", "sha256": fmt.Sprintf("%x", digest)}}}
	}
	if err := writeFileJSON(path, validPayload()); err != nil {
		t.Fatal(err)
	}
	state, ok = loadAutomatedBuildResult(root)
	if !ok || state["status"] != "passed" || state["artifact_count"] != int64(1) {
		t.Fatalf("isolated build should pass: %#v", state)
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"stage failed", func(p map[string]any) { p["stages"].([]any)[1].(map[string]any)["status"] = "failed" }},
		{"return nonzero", func(p map[string]any) { p["stages"].([]any)[1].(map[string]any)["return_code"] = 2 }},
		{"return missing", func(p map[string]any) { delete(p["stages"].([]any)[1].(map[string]any), "return_code") }},
		{"return wrong type", func(p map[string]any) { p["stages"].([]any)[1].(map[string]any)["return_code"] = "0" }},
		{"build passed false", func(p map[string]any) { p["build_passed"] = false }},
		{"build passed missing", func(p map[string]any) { delete(p, "build_passed") }},
		{"duplicate stage", func(p map[string]any) { p["stages"].([]any)[1].(map[string]any)["name"] = "configure" }},
		{"missing stage", func(p map[string]any) { p["stages"] = p["stages"].([]any)[:1] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := validPayload()
			tc.mutate(payload)
			if err := writeFileJSON(path, payload); err != nil {
				t.Fatal(err)
			}
			if state, ok := loadAutomatedBuildResult(root); ok {
				t.Fatalf("contradictory passed build must fail closed: %#v", state)
			}
		})
	}
	if err := writeFileJSON(path, validPayload()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadAutomatedBuildResult(root); ok {
		t.Fatalf("artifact hash mismatch must fail closed: %#v", state)
	}
}

func TestLoadAutomatedBuildResultAcceptsRealFailureShapesWithoutPassingGate(t *testing.T) {
	for _, buildStatus := range []string{"timed_out", "error"} {
		t.Run(buildStatus, func(t *testing.T) {
			root := t.TempDir()
			docs := filepath.Join(root, "project", "docs")
			if err := os.MkdirAll(docs, 0755); err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{
				"schema_version": 1, "status": buildStatus, "build_passed": false, "isolated": true,
				"stages":         []any{map[string]any{"name": "configure", "status": buildStatus, "return_code": nil}},
				"artifact_count": 0, "artifacts": []any{},
			}
			if err := writeFileJSON(filepath.Join(docs, "build-result.json"), payload); err != nil {
				t.Fatal(err)
			}
			state, ok := loadAutomatedBuildResult(root)
			if !ok || state["status"] != buildStatus {
				t.Fatalf("real failure shape must remain visible: %#v", state)
			}
			reconstruction := applyAutomatedBuildState(ReconstructionState{}, state)
			if reconstruction.BuildPassed || reconstruction.Iteration != 0 {
				t.Fatalf("failure must not pass build gate: %#v", reconstruction)
			}
			delete(payload, "build_passed")
			if err := writeFileJSON(filepath.Join(docs, "build-result.json"), payload); err != nil {
				t.Fatal(err)
			}
			if state, ok = loadAutomatedBuildResult(root); !ok || state["status"] != buildStatus {
				t.Fatalf("omitted false build_passed must be compatible: %#v", state)
			}
		})
	}
}

func TestBuildIsolationRequiresContainerOrExplicitHostOptIn(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isolated, mode := buildIsolation()
		if !isolated || mode != "container" {
			t.Fatalf("container isolation not detected: %v %s", isolated, mode)
		}
		return
	}
	t.Setenv("REVERSE_ANALYZER_ALLOW_HOST_BUILD", "")
	if isolated, mode := buildIsolation(); isolated || mode != "host" {
		t.Fatalf("host build must be gated: %v %s", isolated, mode)
	}
	t.Setenv("REVERSE_ANALYZER_ALLOW_HOST_BUILD", "1")
	if isolated, mode := buildIsolation(); !isolated || mode != "explicit-host-test" {
		t.Fatalf("explicit test host build not enabled: %v %s", isolated, mode)
	}
}

func TestLoadBehaviorValidationRequiresRealSubprocessProvenance(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "project", "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(docs, "behavior-validation.json")
	payload := validBehaviorValidationPayload()
	payload["provenance"].(map[string]any)["validator"].(map[string]any)["runner_injected"] = true
	if err := writeFileJSON(path, payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok || state["strictly_verified"] != false {
		t.Fatalf("injected validation must not pass: %#v", state)
	}
	payload["provenance"].(map[string]any)["validator"].(map[string]any)["runner_injected"] = false
	if err := writeFileJSON(path, payload); err != nil {
		t.Fatal(err)
	}
	state, ok = loadBehaviorValidationResult(root)
	if !ok || state["strictly_verified"] != true {
		t.Fatalf("real subprocess validation should pass: %#v", state)
	}
}

func TestLoadBehaviorValidationUsesNestedSummaryCounts(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "project", "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"status":              "passed",
		"behavior_equivalent": true,
		"comparison_count":    99,
		"mismatch_count":      98,
		"summary": map[string]any{
			"comparison_count":            7,
			"mismatched_comparison_count": 2,
		},
		"provenance": map[string]any{"validator": map[string]any{
			"real_subprocess": true,
			"runner_injected": false,
			"shell":           false,
		}},
	}
	if err := writeFileJSON(filepath.Join(docs, "behavior-validation.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok {
		t.Fatal("expected behavior validation artifact")
	}
	if state["comparison_count"] != int64(7) || state["mismatch_count"] != int64(2) {
		t.Fatalf("nested summary counts must take precedence: %#v", state)
	}
}

func TestLoadBehaviorValidationSupportsLegacyTopLevelCounts(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "project", "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"status":              "passed",
		"behavior_equivalent": true,
		"comparison_count":    5,
		"mismatch_count":      1,
		"provenance": map[string]any{"validator": map[string]any{
			"real_subprocess": true,
			"runner_injected": false,
			"shell":           false,
		}},
	}
	if err := writeFileJSON(filepath.Join(docs, "behavior-validation.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok {
		t.Fatal("expected behavior validation artifact")
	}
	if state["comparison_count"] != int64(5) || state["mismatch_count"] != int64(1) {
		t.Fatalf("legacy top-level counts must remain supported: %#v", state)
	}
	if state["strictly_verified"] != false {
		t.Fatalf("legacy artifact without schema and isolation evidence must not pass: %#v", state)
	}
}

func TestLoadBehaviorValidationStrictVerificationGate(t *testing.T) {
	valid := map[string]any{
		"schema_version":      1,
		"status":              "passed",
		"behavior_equivalent": true,
		"isolated":            true,
		"comparison_count":    1,
		"real_subprocess":     true,
		"runner_injected":     false,
		"shell":               false,
	}
	cases := []struct {
		name  string
		field string
		value any
	}{
		{name: "status", field: "status", value: "failed"},
		{name: "schema version", field: "schema_version", value: 2},
		{name: "schema missing", field: "schema_version", value: nil},
		{name: "behavior equivalent", field: "behavior_equivalent", value: false},
		{name: "isolated", field: "isolated", value: false},
		{name: "isolation missing", field: "isolated", value: nil},
		{name: "no comparisons", field: "comparison_count", value: 0},
		{name: "real subprocess", field: "real_subprocess", value: false},
		{name: "runner injected", field: "runner_injected", value: true},
		{name: "shell", field: "shell", value: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			docs := filepath.Join(root, "docs")
			if err := os.MkdirAll(docs, 0755); err != nil {
				t.Fatal(err)
			}
			values := make(map[string]any, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			values[tc.field] = tc.value
			payload := map[string]any{
				"schema_version":      values["schema_version"],
				"status":              values["status"],
				"behavior_equivalent": values["behavior_equivalent"],
				"summary": map[string]any{
					"comparison_count":            values["comparison_count"],
					"mismatched_comparison_count": 0,
				},
				"archive_validation": map[string]any{"isolated": values["isolated"]},
				"provenance": map[string]any{"validator": map[string]any{
					"real_subprocess": values["real_subprocess"],
					"runner_injected": values["runner_injected"],
					"shell":           values["shell"],
				}},
			}
			if err := writeFileJSON(filepath.Join(docs, "behavior-validation.json"), payload); err != nil {
				t.Fatal(err)
			}
			state, ok := loadBehaviorValidationResult(root)
			if !ok || state["strictly_verified"] != false {
				t.Fatalf("invalid %s must fail strict verification: %#v", tc.field, state)
			}
		})
	}
}

func TestLoadBehaviorValidationRejectsUntrustedNameCollisions(t *testing.T) {
	root := t.TempDir()
	forgedPaths := []string{
		filepath.Join(root, "behavior-validation.json"),
		filepath.Join(root, "package", "behavior-validation.json"),
		filepath.Join(root, "package", "docs", "behavior-validation.json"),
		filepath.Join(root, "unrelated", "docs", "behavior-validation.json"),
	}
	for _, path := range forgedPaths {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := writeFileJSON(path, validBehaviorValidationPayload()); err != nil {
			t.Fatal(err)
		}
	}
	if state, ok := loadBehaviorValidationResult(root); ok {
		t.Fatalf("untrusted same-name artifact must not be loaded: %#v", state)
	}

	trusted := filepath.Join(root, "archive-workspace-v3", "project", "docs", "behavior-validation.json")
	if err := os.MkdirAll(filepath.Dir(trusted), 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeFileJSON(trusted, validBehaviorValidationPayload()); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok || state["strictly_verified"] != true || state["artifact"] != "archive-workspace-v3/project/docs/behavior-validation.json" {
		t.Fatalf("expected deterministic trusted archive result: %#v", state)
	}
}

func TestLoadBehaviorValidationDeterministicTrustedPathPriority(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		filepath.Join(root, "archive-workspace-v3", "project", "docs", "behavior-validation.json"),
		filepath.Join(root, "project", "docs", "behavior-validation.json"),
		filepath.Join(root, "docs", "behavior-validation.json"),
	}
	for index, path := range paths {
		payload := validBehaviorValidationPayload()
		payload["summary"].(map[string]any)["comparison_count"] = index + 1
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := writeFileJSON(path, payload); err != nil {
			t.Fatal(err)
		}
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok || state["comparison_count"] != int64(1) {
		t.Fatalf("archive workspace result must have deterministic priority: %#v", state)
	}
}

func TestLoadBehaviorValidationDoesNotFallBackAfterMalformedAuthoritativeArtifact(t *testing.T) {
	root := t.TempDir()
	authoritative := filepath.Join(root, "archive-workspace-v3", "project", "docs", "behavior-validation.json")
	fallback := filepath.Join(root, "project", "docs", "behavior-validation.json")
	for _, path := range []string{authoritative, fallback} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(authoritative, []byte(`{"status":"passed"}{"status":"passed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileJSON(fallback, validBehaviorValidationPayload()); err != nil {
		t.Fatal(err)
	}
	if state, ok := loadBehaviorValidationResult(root); ok {
		t.Fatalf("malformed authoritative result must not fall back to a colliding file: %#v", state)
	}
}

func TestLoadBehaviorValidationInvalidCountsRemainInvalid(t *testing.T) {
	invalidValues := []struct {
		name  string
		value any
	}{
		{name: "missing", value: nil},
		{name: "null", value: nil},
		{name: "string", value: "1"},
		{name: "negative", value: -1},
		{name: "fraction", value: 1.5},
		{name: "too large", value: json.Number("9223372036854775808")},
	}
	for _, tc := range invalidValues {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			docs := filepath.Join(root, "docs")
			if err := os.MkdirAll(docs, 0755); err != nil {
				t.Fatal(err)
			}
			payload := validBehaviorValidationPayload()
			summary := payload["summary"].(map[string]any)
			if tc.name == "missing" {
				delete(summary, "comparison_count")
				delete(payload, "comparison_count")
			} else {
				summary["comparison_count"] = tc.value
				payload["comparison_count"] = 9
			}
			if err := writeFileJSON(filepath.Join(docs, "behavior-validation.json"), payload); err != nil {
				t.Fatal(err)
			}
			state, ok := loadBehaviorValidationResult(root)
			if !ok || state["strictly_verified"] != false || state["comparison_count"] != nil {
				t.Fatalf("invalid nested count must not pass or fall back: %#v", state)
			}
		})
	}
}

func TestLoadBehaviorValidationInvalidMismatchCountFailsStrictGate(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	payload := validBehaviorValidationPayload()
	payload["summary"].(map[string]any)["mismatched_comparison_count"] = "0"
	payload["mismatch_count"] = 0
	if err := writeFileJSON(filepath.Join(docs, "behavior-validation.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok || state["strictly_verified"] != false || state["mismatch_count"] != nil {
		t.Fatalf("invalid nested mismatch count must not pass or fall back: %#v", state)
	}
}

func TestLoadBehaviorValidationNonzeroMismatchFailsStrictGate(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "docs")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	payload := validBehaviorValidationPayload()
	payload["summary"].(map[string]any)["mismatched_comparison_count"] = 1
	if err := writeFileJSON(filepath.Join(docs, "behavior-validation.json"), payload); err != nil {
		t.Fatal(err)
	}
	state, ok := loadBehaviorValidationResult(root)
	if !ok || state["strictly_verified"] != false || state["mismatch_count"] != int64(1) {
		t.Fatalf("nonzero mismatch count must fail strict verification: %#v", state)
	}
}

func TestApplyBehaviorValidationStateClearsPreviousPass(t *testing.T) {
	state := ReconstructionState{BehaviorPassed: true, AnalysisComplete: true, SourceGenerated: true, StructureComplete: true, DependenciesLocked: true, BuildPassed: true}
	state = applyBehaviorValidationState(state, map[string]any{"strictly_verified": false})
	if state.BehaviorPassed || state.CompleteBuildable || !containsString(state.BlockingReasons, "behavior_validation_not_passed") {
		t.Fatalf("failed validation must clear previous pass: %#v", state)
	}
	state = applyBehaviorValidationState(state, map[string]any{"strictly_verified": true})
	if !state.BehaviorPassed || !state.CompleteBuildable {
		t.Fatalf("strict validation should set pass: %#v", state)
	}
}

func validBehaviorValidationPayload() map[string]any {
	return map[string]any{
		"schema_version":      1,
		"status":              "passed",
		"behavior_equivalent": true,
		"summary": map[string]any{
			"comparison_count":            1,
			"mismatched_comparison_count": 0,
		},
		"archive_validation": map[string]any{"isolated": true},
		"provenance": map[string]any{"validator": map[string]any{
			"real_subprocess": true,
			"runner_injected": false,
			"shell":           false,
		}},
	}
}

func TestMultipartUploadCreatesWorkspaceTarget(t *testing.T) {
	s, _ := testServer(t, "")
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "sample.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("MZ multipart"))
	_ = writer.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/uploads", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatal(w.Body.String())
	}
	var uploaded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &uploaded)
	path := uploaded["path"].(string)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": path, "mode": "pe-reconstruction"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
}

func TestReconstructedSourceWorkspaceLifecycle(t *testing.T) {
	t.Setenv("REVERSE_ANALYZER_ALLOW_HOST_BUILD", "1")
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	project := filepath.Join(root, "experiments", id, "analysis", "reconstructed_test")
	_ = os.MkdirAll(filepath.Join(project, "src"), 0755)
	_ = os.WriteFile(filepath.Join(project, "CMakeLists.txt"), []byte("cmake_minimum_required(VERSION 3.16)\nproject(reconstructed C)\nadd_executable(reconstructed src/main.c)\n"), 0600)
	_ = os.WriteFile(filepath.Join(project, "src", "main.c"), []byte("int main(void) { return 0; }\n"), 0600)

	listed := request(t, s, http.MethodGet, "/api/experiments/"+id+"/source?path=src/main.c", "", nil)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte("int main")) {
		t.Fatal(listed.Body.String())
	}
	saved := request(t, s, http.MethodPut, "/api/experiments/"+id+"/source/file", "", map[string]any{"path": "src/main.c", "content": "int main(void) { return 7; }\n"})
	if saved.Code != http.StatusOK {
		t.Fatal(saved.Body.String())
	}
	content, _ := os.ReadFile(filepath.Join(project, "src", "main.c"))
	if !bytes.Contains(content, []byte("return 7")) {
		t.Fatal(string(content))
	}
	archive := request(t, s, http.MethodGet, "/api/experiments/"+id+"/source/archive", "", nil)
	if archive.Code != http.StatusOK || !bytes.HasPrefix(archive.Body.Bytes(), []byte("PK")) {
		t.Fatal(archive.Code, archive.Body.Len())
	}
	zipReader, zipErr := zip.NewReader(bytes.NewReader(archive.Body.Bytes()), int64(archive.Body.Len()))
	if zipErr != nil {
		t.Fatal(zipErr)
	}
	archiveFiles := map[string]bool{}
	for _, file := range zipReader.File {
		archiveFiles[file.Name] = true
	}
	if !archiveFiles["SOURCE_TREE.json"] || !archiveFiles["BUILD_STATUS.json"] || !archiveFiles["src/main.c"] {
		t.Fatalf("archive is missing source structure metadata: %#v", archiveFiles)
	}
	if _, err := exec.LookPath("cmake"); err == nil {
		built := request(t, s, http.MethodPost, "/api/experiments/"+id+"/build", "", map[string]any{"confirmation": "BUILD_RECONSTRUCTED_SOURCE"})
		if built.Code != http.StatusOK {
			t.Fatal(built.Body.String())
		}
		if _, err = os.Stat(filepath.Join(project, "build-output.log")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSafeProjectFileRejectsSymlinkEscape(t *testing.T) {
	project := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := safeProjectFile(project, "escape/secret.txt"); err == nil {
		t.Fatal("symlink escape must be rejected")
	}
	if path, err := safeProjectFile(project, "src/new.c"); err != nil || path != filepath.Join(project, "src", "new.c") {
		t.Fatalf("normal new file rejected: %s err=%v", path, err)
	}
}

func TestRegistryRBAC(t *testing.T) {
	s, root := testServer(t, "")
	dir := filepath.Join(root, ".reverse_analyzer")
	_ = os.MkdirAll(dir, 0755)
	payload := tokenFile{Tokens: []tokenRecord{{Subject: "reader", Role: "viewer", Workspace: root, TokenHash: tokenHash("read")}}}
	b, _ := json.Marshal(payload)
	_ = os.WriteFile(filepath.Join(dir, "auth.json"), b, 0600)
	if w := request(t, s, "GET", "/api/workspace", "read", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(t, s, "POST", "/api/experiments", "read", map[string]any{}); w.Code != 403 {
		t.Fatalf("viewer mutation=%d", w.Code)
	}
}
func TestTerminalAndToolCallMethodsAndRBAC(t *testing.T) {
	s, root := testServer(t, "")
	authDir := filepath.Join(root, ".reverse_analyzer")
	if err := os.MkdirAll(authDir, 0755); err != nil {
		t.Fatal(err)
	}
	registry := tokenFile{Tokens: []tokenRecord{
		{Subject: "reader", Role: "viewer", Workspace: root, TokenHash: tokenHash("read")},
		{Subject: "operator", Role: "analyst", Workspace: root, TokenHash: tokenHash("operate")},
	}}
	content, _ := json.Marshal(registry)
	if err := os.WriteFile(filepath.Join(authDir, "auth.json"), content, 0600); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("e", 32)
	x := Experiment{ID: id, Status: "completed", CreatedAt: now(), UpdatedAt: now(), Orchestration: &OrchestrationState{ToolCalls: []OrchestrationToolCall{{ID: "tool-1", Name: "fixture", Status: "failed"}}}}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "experiments", id, "analysis", "reconstructed_archive_fixture")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "CMakeLists.txt"), []byte("cmake_minimum_required(VERSION 3.10)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if response := request(t, s, http.MethodGet, "/api/experiments/"+id+"/terminal", "read", nil); response.Code != http.StatusForbidden {
		t.Fatalf("viewer terminal read=%d %s", response.Code, response.Body.String())
	}
	if response := request(t, s, http.MethodPut, "/api/experiments/"+id+"/terminal", "operate", map[string]any{"command": "echo no"}); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("terminal PUT=%d %s", response.Code, response.Body.String())
	}
	if response := request(t, s, http.MethodGet, "/api/experiments/"+id+"/tool-calls/tool-1/retry", "operate", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("tool retry GET=%d %s", response.Code, response.Body.String())
	}
	if response := request(t, s, http.MethodPost, "/api/experiments/"+id+"/tool-calls/tool-1/retry", "read", nil); response.Code != http.StatusForbidden {
		t.Fatalf("viewer tool retry=%d %s", response.Code, response.Body.String())
	}
}

func TestToolCallRetryCreatesDependencyGatedSuccessor(t *testing.T) {
	s, _ := testServer(t, "secret")
	id := strings.Repeat("d", 32)
	original := OrchestrationToolCall{ID: "tool-original", Name: "historical-provider", Status: "failed", Result: "original failure", Timestamp: now()}
	experiment := Experiment{ID: id, Name: "fixture", Status: "completed", CreatedAt: now(), UpdatedAt: now(), Orchestration: &OrchestrationState{ToolCalls: []OrchestrationToolCall{original}}}
	if err := s.saveExperiment(experiment); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, http.MethodPost, "/api/experiments/"+id+"/tool-calls/"+original.ID+"/retry", "secret", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("retry=%d %s", response.Code, response.Body.String())
	}
	current, err := s.loadExperiment(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Orchestration.ToolCalls) != 2 {
		t.Fatalf("tool calls=%d want=2", len(current.Orchestration.ToolCalls))
	}
	source := current.Orchestration.ToolCalls[0]
	successor := current.Orchestration.ToolCalls[1]
	if source.Status != "failed" || source.Result != "original failure" || source.RetryOf != "" {
		t.Fatalf("original tool call mutated: %#v", source)
	}
	if successor.ID == source.ID || successor.RetryOf != source.ID || successor.RootID != source.ID || successor.Attempt != 2 {
		t.Fatalf("invalid successor chain: source=%#v successor=%#v", source, successor)
	}
	if successor.Status != "dependency-gated" || successor.EndedAt == "" {
		t.Fatalf("unknown tool must be dependency-gated: %#v", successor)
	}
	events, err := s.events(id)
	if err != nil {
		t.Fatal(err)
	}
	current = s.ensureOrchestrationState(current, events)
	if len(current.Orchestration.ToolCalls) != 2 {
		t.Fatalf("control event created duplicate tool call: %#v", current.Orchestration.ToolCalls)
	}
}

func TestToolCallCancelPreservesCancelledTerminalState(t *testing.T) {
	s, _ := testServer(t, "secret")
	started := make(chan struct{})
	release := make(chan struct{})
	s.toolExecutors["replayable-fixture"] = func(ctx context.Context, _ Experiment, _ OrchestrationToolCall) (string, error) {
		close(started)
		<-release
		return "late completion", nil
	}
	id := strings.Repeat("c", 32)
	original := OrchestrationToolCall{ID: "tool-replayable", RootID: "tool-replayable", Attempt: 1, Name: "replayable-fixture", Status: "failed", Result: "failed"}
	experiment := Experiment{ID: id, Name: "fixture", Status: "completed", CreatedAt: now(), UpdatedAt: now(), Orchestration: &OrchestrationState{ToolCalls: []OrchestrationToolCall{original}}}
	if err := s.saveExperiment(experiment); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, http.MethodPost, "/api/experiments/"+id+"/tool-calls/"+original.ID+"/retry", "secret", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("retry=%d %s", response.Code, response.Body.String())
	}
	var payload struct {
		ToolCall OrchestrationToolCall `json:"tool_call"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("tool call executor did not start")
	}
	response = request(t, s, http.MethodPost, "/api/experiments/"+id+"/tool-calls/"+payload.ToolCall.ID+"/cancel", "secret", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("cancel=%d %s", response.Code, response.Body.String())
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		current, err := s.loadExperiment(id)
		if err != nil {
			t.Fatal(err)
		}
		call := current.Orchestration.ToolCalls[1]
		if call.Status == "cancelled" && call.Result == "已取消" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancelled state was overwritten: %#v", call)
		}
		time.Sleep(10 * time.Millisecond)
	}
	response = request(t, s, http.MethodPost, "/api/experiments/"+id+"/tool-calls/"+payload.ToolCall.ID+"/cancel", "secret", nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate cancel=%d %s", response.Code, response.Body.String())
	}
}

func TestTerminalOutputIsBounded(t *testing.T) {
	session := &terminalSession{}
	for index := 0; index < terminalMaxLines+50; index++ {
		appendTerminalOutput(session, fmt.Sprintf("line-%04d", index))
	}
	if len(session.Output) != terminalMaxLines || !session.Truncated || session.DroppedLines != 50 {
		t.Fatalf("terminal line limit not enforced: count=%d dropped=%d truncated=%v", len(session.Output), session.DroppedLines, session.Truncated)
	}
	if session.OutputBytes > terminalMaxBytes {
		t.Fatalf("terminal byte limit exceeded: %d", session.OutputBytes)
	}
	appendTerminalOutput(session, strings.Repeat("x", terminalMaxBytes+1024))
	if session.OutputBytes > terminalMaxBytes || len(fmt.Sprint(session.Output[len(session.Output)-1]["line"])) >= terminalMaxBytes {
		t.Fatalf("oversized terminal line not bounded: bytes=%d", session.OutputBytes)
	}
}

func TestAuthStatusIsPublicAndOAuthIsGated(t *testing.T) {
	s, _ := testServer(t, "secret")
	if w := request(t, s, "GET", "/api/auth/status", "", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(t, s, "GET", "/api/auth/oauth/github/start", "", nil); w.Code != 404 {
		t.Fatalf("oauth status %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthStatePersistsAcrossRestartAndConsumesOnce(t *testing.T) {
	s, root := testServer(t, "root-token")
	state := "raw-oauth-state"
	redirect := "https://console.example/api/auth/oauth/github/callback"
	if err := s.storeOAuthState(state, redirect, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(root, ".reverse_analyzer", "auth.json"))
	if err != nil || bytes.Contains(stored, []byte(state)) || !bytes.Contains(stored, []byte(tokenHash(state))) {
		t.Fatalf("OAuth state was not stored as a hash: %s err=%v", stored, err)
	}
	restarted := newServer(s.cfg)
	if err := restarted.consumeOAuthState(state, redirect, time.Now()); err != nil {
		t.Fatalf("restart could not consume state: %v", err)
	}
	if err := restarted.consumeOAuthState(state, redirect, time.Now()); err == nil {
		t.Fatal("OAuth state was consumed twice")
	}
}

func TestOAuthStateRejectsExpiryAndRedirectMismatch(t *testing.T) {
	s, _ := testServer(t, "root-token")
	if err := s.storeOAuthState("expired", "https://console.example/callback", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.consumeOAuthState("expired", "https://console.example/callback", time.Now()); err == nil {
		t.Fatal("expired OAuth state was accepted")
	}
	if err := s.storeOAuthState("redirect", "https://console.example/callback", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.consumeOAuthState("redirect", "https://attacker.example/callback", time.Now()); err == nil {
		t.Fatal("OAuth state was accepted for another redirect")
	}
}

func TestOAuthExchangeCodeReturnsTokenOnceWithoutPersistingPlaintext(t *testing.T) {
	s, root := testServer(t, "root-token")
	code := "one-time-exchange-code"
	if err := s.storeOAuthExchangeCode(code, "github:operator", "analyst", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	token, err := s.consumeOAuthExchangeCode(code, time.Now())
	if err != nil || len(token) < 32 {
		t.Fatalf("exchange failed: token=%q err=%v", token, err)
	}
	if _, err := s.consumeOAuthExchangeCode(code, time.Now()); err == nil {
		t.Fatal("exchange code was consumed twice")
	}
	if response := request(t, s, http.MethodGet, "/api/workspace", token, nil); response.Code != http.StatusOK {
		t.Fatalf("issued token is unusable: %d %s", response.Code, response.Body.String())
	}
	for _, path := range []string{filepath.Join(root, ".reverse_analyzer", "auth.json")} {
		content, _ := os.ReadFile(path)
		if bytes.Contains(content, []byte(code)) || bytes.Contains(content, []byte(token)) {
			t.Fatalf("plaintext OAuth credential persisted in %s", path)
		}
	}
}

func TestOAuthExchangeHTTPConsumesOnceAndAuditsWithoutTokenLeak(t *testing.T) {
	s, root := testServer(t, "root-token")
	code := "one-time-http-exchange-code"
	if err := s.storeOAuthExchangeCode(code, "github:operator", "analyst", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first := request(t, s, http.MethodPost, "/api/auth/oauth/exchange", "", map[string]any{"code": code})
	if first.Code != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", first.Code, first.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(first.Body.Bytes(), &payload); err != nil || len(payload["token"]) < 32 {
		t.Fatalf("exchange response=%q err=%v", first.Body.String(), err)
	}
	second := request(t, s, http.MethodPost, "/api/auth/oauth/exchange", "", map[string]any{"code": code})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("reused exchange status=%d body=%s", second.Code, second.Body.String())
	}
	audit, err := os.ReadFile(filepath.Join(root, ".reverse_analyzer", "audit", "events.jsonl"))
	if err != nil || !bytes.Contains(audit, []byte("oauth.exchange")) || !bytes.Contains(audit, []byte("succeeded")) || !bytes.Contains(audit, []byte("failed")) {
		t.Fatalf("missing OAuth exchange audit evidence: %s err=%v", audit, err)
	}
	if bytes.Contains(audit, []byte(code)) || bytes.Contains(audit, []byte(payload["token"])) {
		t.Fatalf("OAuth credential leaked into audit log: %s", audit)
	}
}

func TestP10AcceptanceDocumentIsUTF8AndReadable(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "acceptance", "p10_platform_production.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(content) {
		t.Fatal("P10 acceptance document must be valid UTF-8")
	}
	text := string(content)
	for _, required := range []string{"多用户", "OAuth", "complete_buildable"} {
		if !strings.Contains(text, required) {
			t.Fatalf("P10 acceptance document missing %q", required)
		}
	}
}
func TestOrchestrationProjectionExposesPentAGIStyleHierarchy(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(sample, []byte("MZ"), 0600); err != nil {
		t.Fatal(err)
	}
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin", "mode": "pe-reconstruction"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var createdPayload map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &createdPayload); err != nil {
		t.Fatal(err)
	}
	id := createdPayload["experiment"].(map[string]any)["id"].(string)
	s.appendEvent(id, "provider_broker_started", "running", "模型请求代理已启动", map[string]any{"model": "fixture"})
	response := request(t, s, http.MethodGet, "/api/experiments/"+id+"/orchestration", "", nil)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["flow"].(map[string]any); !ok {
		t.Fatalf("flow missing: %#v", payload)
	}
	if len(payload["tasks"].([]any)) != 1 || len(payload["subtasks"].([]any)) != 3 || len(payload["tool_calls"].([]any)) != 1 || len(payload["logs"].([]any)) < 2 {
		t.Fatalf("unexpected orchestration projection: %#v", payload)
	}
	subtasks := payload["subtasks"].([]any)
	first := subtasks[0].(map[string]any)
	if first["status"] != "running" {
		t.Fatalf("provider event should advance persisted subtask state: %#v", first)
	}
}

func TestOrchestrationStatePersistsAndResumes(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(sample, []byte("MZ"), 0600); err != nil {
		t.Fatal(err)
	}
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin", "mode": "pe-reconstruction"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	id := payload["experiment"].(map[string]any)["id"].(string)
	initial, err := s.loadExperiment(id)
	if err != nil || initial.Orchestration == nil || len(initial.Orchestration.Subtasks) != 3 {
		t.Fatalf("initial orchestration state missing: %#v err=%v", initial.Orchestration, err)
	}
	s.appendEvent(id, "started", "running", "任务执行器已启动", nil)
	s.appendEvent(id, "result_summary", "running", "执行日志已归档", map[string]any{"output_lines": 2})
	s.appendEvent(id, "model_completed", "completed", "模型重构阶段已完成", map[string]any{"model": "fixture"})
	current, err := s.loadExperiment(id)
	if err != nil || current.Orchestration == nil {
		t.Fatalf("orchestration state not persisted: %#v err=%v", current.Orchestration, err)
	}
	if current.Orchestration.Subtasks[0].Status != "finished" || current.Orchestration.Subtasks[1].Status != "running" {
		t.Fatalf("unexpected subtask states: %#v", current.Orchestration.Subtasks)
	}
	if len(current.Orchestration.ToolCalls) != 1 || current.Orchestration.LastEventSequence == 0 {
		t.Fatalf("tool call or sequence was not persisted: %#v", current.Orchestration)
	}
	restarted := newServer(s.cfg)
	defer restarted.close()
	recovered, err := restarted.loadExperiment(id)
	if err != nil || recovered.Orchestration == nil || len(recovered.Orchestration.ToolCalls) != 1 {
		t.Fatalf("orchestration state did not survive restart: %#v err=%v", recovered.Orchestration, err)
	}
}

func TestTemplatesAndCompletedEventStream(t *testing.T) {
	s, root := testServer(t, "")
	if w := request(t, s, "GET", "/api/flow-templates", "", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	w := request(t, s, "POST", "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	x, _ := s.loadExperiment(id)
	x = s.status(x, "cancelled", "test")
	_ = s.saveExperiment(x)
	s.appendEvent(id, "cancelled", "cancelled", "done", nil)
	stream := request(t, s, "GET", "/api/experiments/"+id+"/stream", "", nil)
	if stream.Code != 200 || !bytes.Contains(stream.Body.Bytes(), []byte("event: close")) {
		t.Fatal(stream.Body.String())
	}
}

func TestRawWorkerOutputIsExcludedFromDefaultEventFeeds(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	s.appendEvent(id, "output", "running", `{"chunk":"noise"}`, nil)
	s.appendEvent(id, "result_summary", "running", "output archived", map[string]any{"output_lines": 1})
	filtered := request(t, s, http.MethodGet, "/api/experiments/"+id+"/events", "", nil)
	if bytes.Contains(filtered.Body.Bytes(), []byte(`chunk`)) || !bytes.Contains(filtered.Body.Bytes(), []byte("output archived")) {
		t.Fatal(filtered.Body.String())
	}
	raw := request(t, s, http.MethodGet, "/api/experiments/"+id+"/events?raw=1", "", nil)
	if !bytes.Contains(raw.Body.Bytes(), []byte(`chunk`)) {
		t.Fatal(raw.Body.String())
	}
}

func TestEventSequenceCacheResumesWithoutRescanningOnEachAppend(t *testing.T) {
	s, _ := testServer(t, "")
	id := newID()
	s.appendEvent(id, "first", "running", "one", nil)
	s.appendEvent(id, "second", "running", "two", nil)
	if s.eventSeq[id] != 2 {
		t.Fatalf("cached sequence=%d", s.eventSeq[id])
	}
	restarted := newServer(s.cfg)
	restarted.appendEvent(id, "third", "running", "three", nil)
	events, err := restarted.events(id)
	if err != nil || len(events) != 3 || events[2].Sequence != 3 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}
func TestStaticSPA(t *testing.T) {
	s, _ := testServer(t, "")
	w := request(t, s, "GET", "/flows/123", "", nil)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("go")) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestKnowledgeLifecycle(t *testing.T) {
	s, _ := testServer(t, "")
	created := request(t, s, http.MethodPost, "/api/knowledge", "", map[string]any{"title": "初始标题", "content": "证据"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var doc map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &doc)
	id := doc["id"].(string)
	updated := request(t, s, http.MethodPatch, "/api/knowledge/"+id, "", map[string]any{"title": "更新标题"})
	if updated.Code != http.StatusOK {
		t.Fatal(updated.Body.String())
	}
	_ = json.Unmarshal(updated.Body.Bytes(), &doc)
	if doc["title"] != "更新标题" || doc["content"] != "证据" {
		t.Fatalf("unexpected document: %#v", doc)
	}
	deleted := request(t, s, http.MethodDelete, "/api/knowledge/"+id, "", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatal(deleted.Code, deleted.Body.String())
	}
	missing := request(t, s, http.MethodPatch, "/api/knowledge/"+id, "", map[string]any{"title": "missing"})
	if missing.Code != http.StatusNotFound {
		t.Fatal(missing.Code, missing.Body.String())
	}
}

func TestProviderConfigurationAndFallback(t *testing.T) {
	s, _ := testServer(t, "")
	profile := map[string]any{
		"name": "local_gateway", "kind": "openai-compatible", "model": "analysis-model",
		"base_url": "http://127.0.0.1:9999/v1", "api_key_env": "TEST_PROVIDER_KEY", "enabled": true, "priority": 5,
	}
	updated := request(t, s, http.MethodPut, "/api/providers", "", profile)
	if updated.Code != http.StatusOK {
		t.Fatal(updated.Body.String())
	}
	listed := request(t, s, http.MethodGet, "/api/providers", "", nil)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte("local_gateway")) {
		t.Fatal(listed.Body.String())
	}
	tested := request(t, s, http.MethodPost, "/api/providers/test", "", map[string]any{"name": "local_gateway"})
	if tested.Code != http.StatusOK || !bytes.Contains(tested.Body.Bytes(), []byte("dependency-gated")) {
		t.Fatal(tested.Body.String())
	}
	selected, fallback := s.selectProvider("local_gateway")
	if selected.Name != "rule_based" || !fallback {
		t.Fatalf("expected rule fallback, got %#v fallback=%v", selected, fallback)
	}
	rejected := request(t, s, http.MethodPut, "/api/providers", "", map[string]any{"name": "rule_based", "kind": "local", "enabled": false})
	if rejected.Code != http.StatusBadRequest {
		t.Fatal(rejected.Code, rejected.Body.String())
	}
}

func TestTokenLifecycle(t *testing.T) {
	s, root := testServer(t, "root-token")
	created := request(t, s, http.MethodPost, "/api/auth/tokens", "root-token", map[string]any{"Subject": "operator", "Role": "analyst", "Workspace": "another-workspace"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["id"].(string)
	if payload["workspace"] != root {
		t.Fatalf("token escaped current workspace: %#v", payload)
	}
	issuedToken, _ := payload["token"].(string)
	if len(issuedToken) < 32 {
		t.Fatalf("server did not return a strong one-time token: %#v", payload)
	}
	listed := request(t, s, http.MethodGet, "/api/auth/tokens", "root-token", nil)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(id)) || bytes.Contains(listed.Body.Bytes(), []byte("token_hash")) || bytes.Contains(listed.Body.Bytes(), []byte(issuedToken)) {
		t.Fatal(listed.Body.String())
	}
	if allowed := request(t, s, http.MethodGet, "/api/workspace", issuedToken, nil); allowed.Code != http.StatusOK {
		t.Fatal(allowed.Code, allowed.Body.String())
	}
	deleted := request(t, s, http.MethodDelete, "/api/auth/tokens/"+id, "root-token", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatal(deleted.Code, deleted.Body.String())
	}
	if revoked := request(t, s, http.MethodGet, "/api/workspace", issuedToken, nil); revoked.Code != http.StatusUnauthorized {
		t.Fatal(revoked.Code, revoked.Body.String())
	}
	auditPath := filepath.Join(root, ".reverse_analyzer", "audit", "events.jsonl")
	audit, err := os.ReadFile(auditPath)
	var auditEntry map[string]any
	if err == nil {
		err = json.Unmarshal(bytes.Split(bytes.TrimSpace(audit), []byte("\n"))[0], &auditEntry)
	}
	if err != nil || auditEntry["actor"] != "legacy-web-token" || auditEntry["role"] != "admin" || auditEntry["workspace"] != root {
		t.Fatalf("token lifecycle audit missing actor/role/workspace: %s err=%v", audit, err)
	}
}

func TestAuditDescriptorCoversCriticalWrites(t *testing.T) {
	tests := map[string]string{
		http.MethodPost + " /api/experiments":                                                        "experiment.create",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/execute":                "experiment.execute",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/cancel":                 "experiment.cancel",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/retry":                  "experiment.retry",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/build":                  "source.build",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/terminal":               "terminal.execute",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/terminal/session/stop":  "terminal.cancel",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/tool-calls/tool/retry":  "tool.retry",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/tool-calls/tool/cancel": "tool.cancel",
		http.MethodPut + " /api/experiments/" + strings.Repeat("a", 32) + "/source/file":             "source.save",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/patches/apply":          "patch.apply",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/patches/rollback":       "patch.rollback",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/patches/ai-apply":       "patch.apply",
		http.MethodPost + " /api/experiments/" + strings.Repeat("a", 32) + "/patches/ai-rollback":    "patch.rollback",
		http.MethodPut + " /api/providers":                                                           "provider.update",
		http.MethodPost + " /api/providers/test":                                                     "provider.test",
		http.MethodPost + " /api/knowledge":                                                          "knowledge.create",
		http.MethodPatch + " /api/knowledge/" + strings.Repeat("b", 32):                              "knowledge.update",
		http.MethodDelete + " /api/knowledge/" + strings.Repeat("b", 32):                             "knowledge.delete",
		http.MethodPost + " /api/auth/tokens":                                                        "token.create",
		http.MethodDelete + " /api/auth/tokens/" + strings.Repeat("c", 32):                           "token.revoke",
	}
	for input, expected := range tests {
		parts := strings.SplitN(input, " ", 2)
		r := httptest.NewRequest(parts[0], parts[1], nil)
		descriptor, ok := auditDescriptor(r)
		if !ok || descriptor.Action != expected {
			t.Fatalf("%s => %#v ok=%v, want %s", input, descriptor, ok, expected)
		}
	}
}

func TestMutationAuditRecordsFailureWithoutRequestSecrets(t *testing.T) {
	s, root := testServer(t, "root-token")
	id := strings.Repeat("d", 32)
	x := Experiment{ID: id, Status: "queued", CreatedAt: now(), UpdatedAt: now()}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	secret := "must-never-enter-audit"
	response := request(t, s, http.MethodPost, "/api/experiments/"+id+"/execute", "root-token", map[string]any{"confirmation": secret})
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected failed mutation, got %d", response.Code)
	}
	audit, err := os.ReadFile(filepath.Join(root, ".reverse_analyzer", "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(audit, []byte(`"action":"experiment.execute"`)) || !bytes.Contains(audit, []byte(`"outcome":"failed"`)) || bytes.Contains(audit, []byte(secret)) {
		t.Fatalf("invalid mutation audit: %s", audit)
	}
}

func TestReadinessRequiresHealthyAuthenticatedRunner(t *testing.T) {
	s, _ := testServer(t, "")
	s.cfg.Production = true
	response := request(t, s, http.MethodGet, "/readyz", "", nil)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "isolated runner is not configured") {
		t.Fatalf("missing runner readiness status=%d body=%s", response.Code, response.Body.String())
	}
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Runner-Token") != "runner-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))
	defer runner.Close()
	s.cfg.RunnerURL = runner.URL
	s.cfg.RunnerToken = "runner-secret"
	response = request(t, s, http.MethodGet, "/readyz", "", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"runner":"ready"`) {
		t.Fatalf("healthy runner readiness status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMutationAuditFailurePreventsSuccessResponseAndDegradesReadiness(t *testing.T) {
	s, root := testServer(t, "")
	auditPath := filepath.Join(root, ".reverse_analyzer", "audit")
	if err := os.MkdirAll(filepath.Dir(auditPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, []byte("blocks audit directory"), 0600); err != nil {
		t.Fatal(err)
	}
	sample := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(sample, []byte("MZ"), 0600); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d body=%s", response.Code, response.Body.String())
	}
	ready := request(t, s, http.MethodGet, "/readyz", "", nil)
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), "audit persistence degraded") {
		t.Fatalf("readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
}

func TestRestartRecoversInterruptedExperiment(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	experiment, _ := s.loadExperiment(id)
	experiment = s.status(experiment, "running", "test interruption")
	experiment.Reconstruction = ReconstructionState{AnalysisComplete: true, SourceGenerated: true, StructureComplete: true, DependenciesLocked: true, BuildPassed: true, BehaviorPassed: true, CompleteBuildable: true}
	_ = s.saveExperiment(experiment)
	restarted := newServer(s.cfg)
	recovered, err := restarted.loadExperiment(id)
	if err != nil || recovered.Status != "failed" || !strings.Contains(recovered.Error, "restart") {
		t.Fatalf("recovery failed: %#v err=%v", recovered, err)
	}
	if recovered.Reconstruction.BuildPassed || recovered.Reconstruction.BehaviorPassed || recovered.Reconstruction.CompleteBuildable {
		t.Fatalf("restart recovery retained unprovable completion gates: %#v", recovered.Reconstruction)
	}
}

func TestWorkerFinalizationCannotOverwriteCancelledExperiment(t *testing.T) {
	s, _ := testServer(t, "")
	id := newID()
	createdAt := now()
	running := Experiment{ID: id, Status: "running", CreatedAt: createdAt, UpdatedAt: createdAt, Metadata: map[string]any{}}
	if err := s.saveExperiment(running); err != nil {
		t.Fatal(err)
	}
	cancelled, err := s.cancel(id)
	if err != nil || cancelled.Status != "cancelled" {
		t.Fatalf("cancel failed: %#v err=%v", cancelled, err)
	}
	completed := running
	completed.Status = "completed"
	completed.UpdatedAt = now()
	if err = s.finalizeWorkerExperiment(completed, "分析任务已完成", 0); err == nil {
		t.Fatal("late worker finalization must be rejected after cancellation")
	}
	current, err := s.loadExperiment(id)
	if err != nil || current.Status != "cancelled" {
		t.Fatalf("cancelled terminal state was overwritten: %#v err=%v", current, err)
	}
	events, err := s.events(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type == "completed" {
			t.Fatalf("completion event published after rejected finalization: %#v", events)
		}
	}
}

func TestWorkerFinalizationPersistsBeforePublishingTerminalEvent(t *testing.T) {
	s, _ := testServer(t, "")
	id := newID()
	createdAt := now()
	running := Experiment{ID: id, Status: "running", CreatedAt: createdAt, UpdatedAt: createdAt, Metadata: map[string]any{}}
	if err := s.saveExperiment(running); err != nil {
		t.Fatal(err)
	}
	completed := running
	completed.Status = "completed"
	completed.UpdatedAt = now()
	if err := s.finalizeWorkerExperiment(completed, "分析任务已完成", 0); err != nil {
		t.Fatal(err)
	}
	current, err := s.loadExperiment(id)
	if err != nil || current.Status != "completed" {
		t.Fatalf("terminal state was not persisted: %#v err=%v", current, err)
	}
	events, err := s.events(id)
	if err != nil || len(events) != 1 || events[0].Type != "completed" {
		t.Fatalf("terminal event mismatch: %#v err=%v", events, err)
	}
	if current.Orchestration == nil || current.Orchestration.LastEventSequence != events[0].Sequence {
		t.Fatalf("terminal event projection mismatch: %#v", current.Orchestration)
	}
}

func TestConcurrentCancelUsesSingleStateTransition(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.cancel(id)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful cancels=%d want=1", successes)
	}
}

func TestConcurrentRetryCreatesOneSuccessor(t *testing.T) {
	s, root := testServer(t, "")
	id := newID()
	x := Experiment{ID: id, Sample: filepath.Join(root, "sample.bin"), Status: "failed", CreatedAt: now(), UpdatedAt: now(), Metadata: map[string]any{}}
	if err := s.saveExperiment(x); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.retry(id)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful retries=%d want=1", successes)
	}
}

func TestSandboxWorkerReceivesProviderEnvironment(t *testing.T) {
	s, _ := testServer(t, "")
	s.cfg.SandboxRuntime = "docker"
	s.cfg.SandboxImage = "reverse-analyzer:test"
	command := s.workerCommand(context.Background(), []string{"-m", "reverse_analyzer", "analyze"}, []string{"REVERSE_ANALYZER_PROVIDER", "OPENAI_API_KEY"})
	joined := strings.Join(command.Args, " ")
	for _, expected := range []string{"docker run", "--network none", "--env REVERSE_ANALYZER_PROVIDER", "--env OPENAI_API_KEY", "reverse-analyzer:test -m reverse_analyzer analyze"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("sandbox command missing %q: %s", expected, joined)
		}
	}
}

func TestSandboxWorkerCanShareDaemonVisibleNamedWorkspaceVolume(t *testing.T) {
	s, _ := testServer(t, "")
	s.cfg.SandboxRuntime = "docker"
	s.cfg.SandboxImage = "reverse-analyzer:test"
	s.cfg.SandboxWorkspaceVolume = "p11-workspace-abc"
	command := s.workerCommand(context.Background(), []string{"-m", "reverse_analyzer.archive_reconstruct"}, []string{"REVERSE_ANALYZER_PROVIDER_BROKER_DIR"})
	joined := strings.Join(command.Args, " ")
	if !strings.Contains(joined, "type=volume,src=p11-workspace-abc,dst=/workspace") || !strings.Contains(joined, "--network none") {
		t.Fatalf("named volume/network isolation missing: %s", joined)
	}
	if strings.Contains(joined, "type=bind") {
		t.Fatalf("daemon-invisible bind path retained: %s", joined)
	}
}

func TestSandboxModelWorkerEnablesExplicitProviderEgress(t *testing.T) {
	s, _ := testServer(t, "")
	s.cfg.SandboxRuntime = "docker"
	s.cfg.SandboxImage = "reverse-analyzer:test"
	command := s.workerCommandWithNetwork(context.Background(), []string{"-m", "reverse_analyzer", "archive-reconstruct"}, []string{"OPENAI_API_KEY"}, "bridge")
	joined := strings.Join(command.Args, " ")
	if !strings.Contains(joined, "--network bridge") || strings.Contains(joined, "--network none") {
		t.Fatalf("model worker egress was not enabled: %s", joined)
	}
}

func TestCloseCancelsWorkers(t *testing.T) {
	s, _ := testServer(t, "")
	cancelled := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s.running["job"] = cancel
	go func() { <-ctx.Done(); close(cancelled) }()
	s.close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("worker was not cancelled")
	}
}

func TestCloseWaitsForWorkerCleanup(t *testing.T) {
	s, _ := testServer(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	s.running["job"] = cancel
	s.workers.Add(1)
	finished := make(chan struct{})
	go func() {
		defer s.workers.Done()
		<-ctx.Done()
		time.Sleep(40 * time.Millisecond)
		close(finished)
	}()
	s.close()
	select {
	case <-finished:
	default:
		t.Fatal("close returned before worker cleanup completed")
	}
}

func TestStartDoesNotDeadlock(t *testing.T) {
	s, root := testServer(t, "")
	s.cfg.Python = "python"
	s.cfg.Timeout = 5 * time.Second
	sample := filepath.Join(root, "sample.bin")
	_ = os.WriteFile(sample, []byte("MZ"), 0600)
	created := request(t, s, "POST", "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	done := make(chan int, 1)
	go func() {
		done <- request(t, s, "POST", "/api/experiments/"+id+"/execute", "", map[string]any{"confirmation": confirmation}).Code
	}()
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("execute status %d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("execute deadlocked")
	}
}

func TestPatchWorkbenchPlansAppliesVerifiesAndRollsBackWithoutTouchingOriginal(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", repo)
	s, root := testServer(t, "")
	original := []byte("MZ\x90\x90HELLO")
	if err = os.WriteFile(filepath.Join(root, "sample.bin"), original, 0600); err != nil {
		t.Fatal(err)
	}
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var createdPayload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &createdPayload)
	id := createdPayload["experiment"].(map[string]any)["id"].(string)

	inspection := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/inspect", "", map[string]any{"offset": "0x2", "length": 2})
	if inspection.Code != http.StatusOK || !strings.Contains(inspection.Body.String(), "9090") {
		t.Fatalf("inspect: %d %s", inspection.Code, inspection.Body.String())
	}
	planned := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/plan", "", map[string]any{"offset": "0x2", "expected_hex": "9090", "replacement_hex": "cccc"})
	if planned.Code != http.StatusOK {
		t.Fatalf("plan: %d %s", planned.Code, planned.Body.String())
	}
	var planPayload map[string]any
	_ = json.Unmarshal(planned.Body.Bytes(), &planPayload)
	patchID := planPayload["patch"].(map[string]any)["id"].(string)
	denied := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/apply", "", map[string]any{"patch_id": patchID})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed apply: %d", denied.Code)
	}
	applied := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/apply", "", map[string]any{"patch_id": patchID, "confirmation": "APPLY_AUTHORIZED_PATCH"})
	if applied.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", applied.Code, applied.Body.String())
	}
	if current, _ := os.ReadFile(filepath.Join(root, "sample.bin")); !bytes.Equal(current, original) {
		t.Fatal("original target was modified")
	}
	verified := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/verify", "", map[string]any{"patch_id": patchID})
	if verified.Code != http.StatusOK || !strings.Contains(verified.Body.String(), `"matches":true`) {
		t.Fatalf("verify: %d %s", verified.Code, verified.Body.String())
	}
	rolledBack := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/rollback", "", map[string]any{"patch_id": patchID, "confirmation": "ROLLBACK_AUTHORIZED_PATCH"})
	if rolledBack.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", rolledBack.Code, rolledBack.Body.String())
	}
	var rollbackPayload map[string]any
	_ = json.Unmarshal(rolledBack.Body.Bytes(), &rollbackPayload)
	restored, _ := s.safePath(rollbackPayload["restored"].(string))
	if current, _ := os.ReadFile(restored); !bytes.Equal(current, original) {
		t.Fatal("rollback output does not match original")
	}
}

func TestAIPatchPlanAppliesHashBoundSourceAndRollsBack(t *testing.T) {
	s, root := testServer(t, "")
	_ = os.WriteFile(filepath.Join(root, "sample.bin"), []byte("MZ"), 0600)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var createdPayload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &createdPayload)
	id := createdPayload["experiment"].(map[string]any)["id"].(string)
	project := filepath.Join(root, "experiments", id, "analysis", "reconstructed_test")
	_ = os.MkdirAll(filepath.Join(project, "src"), 0755)
	_ = os.WriteFile(filepath.Join(project, "CMakeLists.txt"), []byte("project(reconstructed C)\n"), 0600)
	before := []byte("int retry_count = 3;\n")
	path := filepath.Join(project, "src", "config.c")
	_ = os.WriteFile(path, before, 0600)
	plan := aiPatchPlan{ID: newID(), ExperimentID: id, Status: "planned", Mode: "source_edit", Instruction: "重试次数改为 5", CreatedAt: now(), UpdatedAt: now(), Changes: []aiSourceChange{{Path: "src/config.c", BeforeSHA256: sha256Hex(before), Before: string(before), After: "int retry_count = 5;\n", Reason: "按指令修改默认值"}}}
	planRoot := filepath.Join(s.patchRoot(id), "ai", plan.ID)
	_ = os.MkdirAll(planRoot, 0700)
	if err := writeFileJSON(filepath.Join(planRoot, "plan.json"), plan); err != nil {
		t.Fatal(err)
	}
	denied := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/ai-apply", "", map[string]any{"planID": plan.ID})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed apply=%d", denied.Code)
	}
	applied := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/ai-apply", "", map[string]any{"planID": plan.ID, "confirmation": aiPatchConfirmation})
	if applied.Code != http.StatusOK {
		t.Fatal(applied.Body.String())
	}
	if current, _ := os.ReadFile(path); string(current) != "int retry_count = 5;\n" {
		t.Fatalf("not applied: %s", current)
	}
	rolledBack := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/ai-rollback", "", map[string]any{"planID": plan.ID, "confirmation": aiPatchRollbackConfirmation})
	if rolledBack.Code != http.StatusOK {
		t.Fatal(rolledBack.Body.String())
	}
	if current, _ := os.ReadFile(path); !bytes.Equal(current, before) {
		t.Fatalf("not restored: %s", current)
	}
}

func TestAIPatchRejectsSourceChangedAfterPlan(t *testing.T) {
	s, root := testServer(t, "")
	_ = os.WriteFile(filepath.Join(root, "sample.bin"), []byte("MZ"), 0600)
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin"})
	var payload map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &payload)
	id := payload["experiment"].(map[string]any)["id"].(string)
	project := filepath.Join(root, "experiments", id, "analysis", "reconstructed_test")
	_ = os.MkdirAll(filepath.Join(project, "src"), 0755)
	_ = os.WriteFile(filepath.Join(project, "CMakeLists.txt"), []byte("project(x)\n"), 0600)
	path := filepath.Join(project, "src", "main.c")
	_ = os.WriteFile(path, []byte("old\n"), 0600)
	plan := aiPatchPlan{ID: newID(), ExperimentID: id, Status: "planned", Changes: []aiSourceChange{{Path: "src/main.c", BeforeSHA256: sha256Hex([]byte("old\n")), Before: "old\n", After: "new\n"}}}
	planRoot := filepath.Join(s.patchRoot(id), "ai", plan.ID)
	_ = os.MkdirAll(planRoot, 0700)
	_ = writeFileJSON(filepath.Join(planRoot, "plan.json"), plan)
	_ = os.WriteFile(path, []byte("user edit\n"), 0600)
	response := request(t, s, http.MethodPost, "/api/experiments/"+id+"/patches/ai-apply", "", map[string]any{"planID": plan.ID, "confirmation": aiPatchConfirmation})
	if response.Code == http.StatusOK || !strings.Contains(response.Body.String(), "已发生变化") {
		t.Fatalf("hash guard: %d %s", response.Code, response.Body.String())
	}
}

func TestAnalysisArgsRoutesReconstructionZipToArchivePipeline(t *testing.T) {
	x := Experiment{Sample: `C:\workspace\bundle.zip`, Options: map[string]any{"reconstruct": true}}
	args := analysisArgs(x, `C:\workspace\out`)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "reverse_analyzer.archive_reconstruct") || strings.Contains(joined, "reverse_analyzer analyze") {
		t.Fatalf("unexpected archive pipeline args: %s", joined)
	}
	x.Sample = `C:\workspace\client.exe`
	joined = strings.Join(analysisArgs(x, `C:\workspace\out`), " ")
	if !strings.Contains(joined, "reverse_analyzer analyze") || !strings.Contains(joined, "--reconstruct") {
		t.Fatalf("unexpected native pipeline args: %s", joined)
	}
}

func TestAnalysisArgsRouteWorkflowSpecificCommands(t *testing.T) {
	authorized := Experiment{
		Sample: `C:\workspace\target.exe`,
		Metadata: map[string]any{
			"workflow_type":   "authorized_pentest",
			"workflow_params": map[string]any{"objective": "review login surface", "endpoint": "https://example.test/api"},
		},
	}
	joined := strings.Join(analysisArgs(authorized, `C:\workspace\out`), " ")
	for _, expected := range []string{"reverse_analyzer skills route review login surface", "--target C:\\workspace\\target.exe", "--endpoint https://example.test/api", "--limit 3"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("authorized workflow missing %q: %s", expected, joined)
		}
	}

	memory := Experiment{
		Metadata: map[string]any{
			"workflow_type":   "memory_patch",
			"workflow_params": map[string]any{"pid": 4321, "address": "0x401000", "data_hex": "90cc", "expected_hex": "558b"},
		},
	}
	joined = strings.Join(analysisArgs(memory, `C:\workspace\out`), " ")
	for _, expected := range []string{"capability run", "memory_runtime", "--pid 4321", "address=0x401000", "data_hex=90cc", "expected_hex=558b", "--rollback"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("memory workflow missing %q: %s", expected, joined)
		}
	}

	injection := Experiment{
		Metadata: map[string]any{
			"workflow_type":   "process_injection",
			"workflow_params": map[string]any{"pid": 9876, "dll_path": `C:\workspace\mods\agent.dll`, "declared_dll_path": `C:\workspace\mods\agent.dll`, "method": "manual_map"},
		},
	}
	joined = strings.Join(analysisArgs(injection, `C:\workspace\out`), " ")
	for _, expected := range []string{"injector", "--pid 9876", "dll_path=C:\\workspace\\mods\\agent.dll", "declared_dll_path=C:\\workspace\\mods\\agent.dll", "method=manual_map"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("injection workflow missing %q: %s", expected, joined)
		}
	}
}

func TestWorkflowParametersRequireWorkspaceDllAndExistingFile(t *testing.T) {
	s, root := testServer(t, "")
	dllDir := filepath.Join(root, "mods")
	if err := os.MkdirAll(dllDir, 0755); err != nil {
		t.Fatal(err)
	}
	dllPath := filepath.Join(dllDir, "agent.dll")
	if err := os.WriteFile(dllPath, []byte("MZ"), 0600); err != nil {
		t.Fatal(err)
	}
	params, err := s.workflowParameters("process_injection", map[string]any{"pid": 1234, "dll": "mods/agent.dll", "injection_method": "manual_map"})
	if err != nil {
		t.Fatal(err)
	}
	if params["dll_path"] != dllPath || params["declared_dll_path"] != dllPath {
		t.Fatalf("unexpected dll mapping: %#v", params)
	}
	if _, err = s.workflowParameters("process_injection", map[string]any{"pid": 1234, "dll": "../outside.dll"}); err == nil {
		t.Fatal("path escape should be rejected")
	}
	if _, err = s.workflowParameters("process_injection", map[string]any{"pid": 1234, "dll": "mods/missing.dll"}); err == nil {
		t.Fatal("missing dll should be rejected")
	}
}

func TestStartConfirmedPlanOnlyKeepsExperimentPlanned(t *testing.T) {
	s, root := testServer(t, "")
	sample := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(sample, []byte("MZ"), 0600); err != nil {
		t.Fatal(err)
	}
	created := request(t, s, http.MethodPost, "/api/experiments", "", map[string]any{"target": "sample.bin", "workflow_type": "authorized_pentest", "objective": "inspect login flow"})
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	id := payload["experiment"].(map[string]any)["id"].(string)
	response := request(t, s, http.MethodPost, "/api/experiments/"+id+"/execute", "", map[string]any{"confirmation": confirmation})
	if response.Code != http.StatusOK {
		t.Fatalf("execute status=%d body=%s", response.Code, response.Body.String())
	}
	current, err := s.loadExperiment(id)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != "planned" {
		t.Fatalf("plan-only workflow should remain planned: %#v", current)
	}
	if _, running := s.running[id]; running {
		t.Fatal("plan-only workflow must not reserve a running worker")
	}
	events, err := s.events(id)
	if err != nil {
		t.Fatal(err)
	}
	joinedTypes := []string{}
	for _, event := range events {
		joinedTypes = append(joinedTypes, event.Type)
	}
	if !containsString(joinedTypes, "execution_planned") || containsString(joinedTypes, "started") {
		t.Fatalf("unexpected plan-only events: %#v", joinedTypes)
	}
}

func TestTrustedDocsArtifactAcceptsOnlyOneReconstructedProject(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "reconstructed_archive_first", "docs", "build-result.json")
	if err := os.MkdirAll(filepath.Dir(first), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if resolved, ok := trustedDocsArtifact(root, "build-result.json"); !ok || resolved != first {
		t.Fatalf("expected unique reconstructed artifact, got %q %v", resolved, ok)
	}
	second := filepath.Join(root, "reconstructed_archive_second", "docs", "build-result.json")
	if err := os.MkdirAll(filepath.Dir(second), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if resolved, ok := trustedDocsArtifact(root, "build-result.json"); ok || resolved != "" {
		t.Fatalf("multiple reconstructed artifacts must be rejected, got %q %v", resolved, ok)
	}
}

var _ = http.MethodGet
