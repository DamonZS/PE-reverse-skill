package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const confirmation = "EXECUTE_LOCAL_ANALYSIS"
const maxArtifactPreviewBytes int64 = 256 * 1024
const maxRepairLoopBytes int64 = 256 * 1024

type Config struct {
	Workspace, Frontend, Addr, Token, Python string
	SandboxRuntime, SandboxImage             string
	SandboxWorkspaceVolume                   string
	Timeout                                  time.Duration
	Production                               bool
	AllowAnonymous                           bool
	AllowedOrigins                           map[string]bool
	TrustedProxyCIDRs                        []string
	HTTPReadTimeout, HTTPWriteTimeout        time.Duration
	HTTPIdleTimeout                          time.Duration
	MaxHeaderBytes                           int
}
type Experiment struct {
	Schema         int                 `json:"schema"`
	SchemaVersion  int                 `json:"schema_version"`
	ID             string              `json:"id"`
	Sample         string              `json:"sample"`
	Name           string              `json:"name,omitempty"`
	Status         string              `json:"status"`
	CreatedAt      string              `json:"created_at"`
	UpdatedAt      string              `json:"updated_at"`
	Options        map[string]any      `json:"options"`
	Metadata       map[string]any      `json:"metadata"`
	History        []map[string]any    `json:"history"`
	Artifacts      []map[string]any    `json:"artifacts"`
	Summary        any                 `json:"summary"`
	Reconstruction ReconstructionState `json:"reconstruction"`
	Error          string              `json:"error,omitempty"`
}
type ReconstructionState struct {
	Stage              string   `json:"stage"`
	AnalysisComplete   bool     `json:"analysis_complete"`
	SourceGenerated    bool     `json:"source_generated"`
	StructureComplete  bool     `json:"structure_complete"`
	DependenciesLocked bool     `json:"dependencies_locked"`
	BuildPassed        bool     `json:"build_passed"`
	BehaviorPassed     bool     `json:"behavior_passed"`
	CompleteBuildable  bool     `json:"complete_buildable"`
	Iteration          int      `json:"iteration"`
	BlockingReasons    []string `json:"blocking_reasons"`
	UpdatedAt          string   `json:"updated_at,omitempty"`
}
type Event struct {
	Sequence  int64          `json:"sequence"`
	Timestamp string         `json:"timestamp"`
	Type      string         `json:"type"`
	Status    string         `json:"status,omitempty"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data,omitempty"`
}
type PatchRecord struct {
	ID             string `json:"id"`
	ExperimentID   string `json:"experiment_id"`
	Target         string `json:"target"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	Offset         int64  `json:"offset"`
	Length         int64  `json:"length"`
	ExpectedHex    string `json:"expected_hex"`
	ReplacementHex string `json:"replacement_hex"`
	SourceSHA256   string `json:"source_sha256"`
	PatchedSHA256  string `json:"patched_sha256,omitempty"`
	Output         string `json:"output"`
	ArtifactDir    string `json:"artifact_dir"`
	Error          string `json:"error,omitempty"`
}
type Server struct {
	cfg          Config
	mux          *http.ServeMux
	mu           sync.Mutex
	running      map[string]context.CancelFunc
	workers      sync.WaitGroup
	eventSeq     map[string]int64
	db           *sql.DB
	dbErr        error
	auditErr     error
	migrationsOK bool
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	s := newServer(cfg)
	server := newHTTPServer(cfg, s)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		s.close()
	}()
	log.Printf("Go control plane listening on %s", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func newHTTPServer(cfg Config, handler http.Handler) *http.Server {
	readTimeout := cfg.HTTPReadTimeout
	if readTimeout <= 0 {
		readTimeout = 15 * time.Minute
	}
	writeTimeout := cfg.HTTPWriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 2 * time.Hour
	}
	idleTimeout := cfg.HTTPIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	maxHeaderBytes := cfg.MaxHeaderBytes
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 64 << 10
	}
	return &http.Server{Addr: cfg.Addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes}
}
func loadConfig() (Config, error) {
	wd, _ := os.Getwd()
	workspace := env("REVERSE_ANALYZER_WORKSPACE", wd)
	workspace, _ = filepath.Abs(workspace)
	frontend := env("REVERSE_ANALYZER_FRONTEND_DIR", filepath.Join(workspace, "frontend", "dist"))
	if _, err := os.Stat(frontend); err != nil {
		return Config{}, fmt.Errorf("frontend build not found: %s", frontend)
	}
	seconds, _ := strconv.Atoi(env("REVERSE_ANALYZER_JOB_TIMEOUT", "3600"))
	cfg := Config{Workspace: workspace, Frontend: frontend, Addr: env("REVERSE_ANALYZER_WEB_ADDR", "127.0.0.1:8090"), Token: os.Getenv("REVERSE_ANALYZER_WEB_TOKEN"), Python: env("REVERSE_ANALYZER_PYTHON", "python"), SandboxRuntime: strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_SANDBOX_RUNTIME")), SandboxImage: env("REVERSE_ANALYZER_SANDBOX_IMAGE", "reverse-analyzer:web"), SandboxWorkspaceVolume: strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_SANDBOX_WORKSPACE_VOLUME")), Timeout: time.Duration(seconds) * time.Second, Production: strings.EqualFold(env("REVERSE_ANALYZER_ENV", "local-dev"), "production"), AllowAnonymous: strings.EqualFold(os.Getenv("REVERSE_ANALYZER_ALLOW_ANONYMOUS"), "true"), AllowedOrigins: csvSet(os.Getenv("REVERSE_ANALYZER_CORS_ALLOWED_ORIGINS")), TrustedProxyCIDRs: csvValues(os.Getenv("REVERSE_ANALYZER_TRUSTED_PROXY_CIDRS"))}
	cfg.HTTPReadTimeout = envSeconds("REVERSE_ANALYZER_HTTP_READ_TIMEOUT", 900)
	cfg.HTTPWriteTimeout = envSeconds("REVERSE_ANALYZER_HTTP_WRITE_TIMEOUT", 7200)
	cfg.HTTPIdleTimeout = envSeconds("REVERSE_ANALYZER_HTTP_IDLE_TIMEOUT", 90)
	cfg.MaxHeaderBytes, _ = strconv.Atoi(env("REVERSE_ANALYZER_HTTP_MAX_HEADER_BYTES", "65536"))
	if cfg.SandboxWorkspaceVolume != "" {
		validVolume, _ := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, cfg.SandboxWorkspaceVolume)
		if !validVolume {
			return Config{}, errors.New("REVERSE_ANALYZER_SANDBOX_WORKSPACE_VOLUME is invalid")
		}
	}
	if err := validateRuntimeConfig(cfg, os.Getenv("REVERSE_ANALYZER_DATABASE_URL")); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func envSeconds(name string, fallback int) time.Duration {
	seconds, err := strconv.Atoi(env(name, strconv.Itoa(fallback)))
	if err != nil || seconds <= 0 {
		seconds = fallback
	}
	return time.Duration(seconds) * time.Second
}

func csvValues(raw string) []string {
	values := []string{}
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func csvSet(raw string) map[string]bool {
	values := map[string]bool{}
	for _, value := range csvValues(raw) {
		values[value] = true
	}
	return values
}

func validateRuntimeConfig(cfg Config, databaseURL string) error {
	if !cfg.Production {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(databaseURL)), "postgres") {
		return errors.New("production requires REVERSE_ANALYZER_DATABASE_URL with PostgreSQL")
	}
	if cfg.AllowAnonymous || (strings.TrimSpace(cfg.Token) == "" && os.Getenv("REVERSE_ANALYZER_GITHUB_CLIENT_ID") == "" && os.Getenv("REVERSE_ANALYZER_GOOGLE_CLIENT_ID") == "") {
		return errors.New("production requires API token or OAuth authentication and forbids anonymous access")
	}
	return nil
}
func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func newServer(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux(), running: map[string]context.CancelFunc{}, eventSeq: map[string]int64{}}
	s.initDatabase()
	_ = s.deliverAuditOutbox()
	s.recoverInterruptedExperiments()
	s.routes()
	return s
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	security(w)
	if !s.applyCORS(w, r) {
		return
	}
	descriptor, audited := auditDescriptor(r)
	var requestIdentity *identity
	auditWriter := &auditResponseWriter{ResponseWriter: w}
	if audited {
		w = auditWriter
		defer func() {
			status := auditWriter.status
			if status == 0 {
				status = http.StatusOK
			}
			outcome := "succeeded"
			if status >= 400 {
				outcome = "failed"
			}
			auditErr := s.auditAction(r, requestIdentity, descriptor, outcome, status, nil)
			if auditErr == nil {
				auditErr = s.deliverAuditOutbox()
			}
			if auditErr != nil && status < 400 {
				writeJSON(auditWriter.ResponseWriter, http.StatusInternalServerError, map[string]any{"error": "audit persistence failed"})
				return
			}
			auditWriter.flush()
		}()
	}
	publicAPI := r.URL.Path == "/api/health" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/api/auth/status" || strings.HasPrefix(r.URL.Path, "/api/auth/oauth/")
	if strings.HasPrefix(r.URL.Path, "/api/") && !publicAPI {
		if s.dbErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "persistent storage is unavailable"})
			return
		}
		registry := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json")
		_, registryErr := os.Stat(registry)
		authDisabled := !s.cfg.Production && (s.cfg.AllowAnonymous || (s.cfg.Token == "" && s.db == nil && os.IsNotExist(registryErr)))
		if !authDisabled {
			requestIdentity = s.authenticate(r)
			if requestIdentity == nil {
				writeJSON(w, 401, map[string]any{"error": "authentication required"})
				return
			}
			if !requestIdentity.allows(permission(r), s.cfg.Workspace) {
				writeJSON(w, 403, map[string]any{"error": "role or workspace does not permit this operation"})
				return
			}
		}
	}
	if audited && s.maintenanceActive() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "workspace is in coordinated backup maintenance"})
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) maintenanceActive() bool {
	if s.db == nil || s.dbErr != nil {
		return false
	}
	var active bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM platform_maintenance WHERE workspace_id=$1 AND expires_at>now())`, s.cfg.Workspace).Scan(&active); err != nil {
		return true
	}
	return active
}

func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if !s.cfg.AllowedOrigins[origin] {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "origin is not allowed"})
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Add("Vary", "Origin")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	remote := net.ParseIP(host)
	trusted := false
	for _, raw := range s.cfg.TrustedProxyCIDRs {
		_, network, parseErr := net.ParseCIDR(raw)
		if parseErr == nil && remote != nil && network.Contains(remote) {
			trusted = true
			break
		}
	}
	if trusted {
		for _, candidate := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
			if parsed := net.ParseIP(strings.TrimSpace(candidate)); parsed != nil {
				return parsed.String()
			}
		}
	}
	if remote == nil {
		return ""
	}
	return remote.String()
}
func security(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
}
func (s *Server) routes() {
	s.mux.HandleFunc("/api/health", s.health)
	s.mux.HandleFunc("/healthz", s.liveness)
	s.mux.HandleFunc("/readyz", s.readiness)
	s.mux.HandleFunc("/api/auth/status", s.authStatus)
	s.mux.HandleFunc("/api/auth/me", s.authMe)
	s.mux.HandleFunc("/api/auth/tokens", s.authTokens)
	s.mux.HandleFunc("/api/auth/tokens/", s.authTokenItem)
	s.mux.HandleFunc("/api/auth/oauth/", s.oauth)
	s.mux.HandleFunc("/api/workspace", s.workspace)
	s.mux.HandleFunc("/api/platform/catalog", s.catalog)
	s.mux.HandleFunc("/api/environment", s.environment)
	s.mux.HandleFunc("/api/providers", s.providers)
	s.mux.HandleFunc("/api/providers/test", s.providerTest)
	s.mux.HandleFunc("/api/uploads", s.upload)
	s.mux.HandleFunc("/api/experiments", s.experiments)
	s.mux.HandleFunc("/api/experiments/", s.experiment)
	s.mux.HandleFunc("/api/flow-templates", s.flowTemplates)
	s.mux.HandleFunc("/api/artifacts", s.artifact)
	s.mux.HandleFunc("/api/knowledge", s.knowledge)
	s.mux.HandleFunc("/api/knowledge/", s.knowledgeItem)
	s.mux.HandleFunc("/", s.static)
}

func (s *Server) recoverInterruptedExperiments() {
	items, err := s.listExperiments()
	if err != nil {
		return
	}
	for _, experiment := range items {
		if experiment.Status != "running" {
			continue
		}
		experiment = s.status(experiment, "failed", "control plane restarted while worker was running")
		experiment.Error = "worker interrupted by control-plane restart; retry is available"
		experiment.Reconstruction.BuildPassed = false
		experiment.Reconstruction.BehaviorPassed = false
		experiment.Reconstruction.CompleteBuildable = false
		experiment.Reconstruction.BlockingReasons = append(experiment.Reconstruction.BlockingReasons, "worker interrupted; build and behavior evidence must be regenerated")
		if s.saveExperiment(experiment) == nil {
			s.appendEvent(experiment.ID, "recovered", "failed", "服务重启后检测到中断任务，已标记失败并允许重试", nil)
		}
	}
}

func (s *Server) close() {
	s.mu.Lock()
	for id, cancel := range s.running {
		cancel()
		delete(s.running, id)
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		log.Print("timed out waiting for workers during shutdown")
	}
	if s.db != nil {
		_ = s.db.Close()
	}
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := 200
	storage := storageBackend()
	var databaseError any
	if s.dbErr != nil {
		status = "degraded"
		code = 503
		databaseError = s.dbErr.Error()
	}
	if s.auditError() != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "service": "go-control-plane", "workspace": s.cfg.Workspace, "storage": storage, "database_error": databaseError, "generated_at": now()})
}
func (s *Server) liveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "go-control-plane"})
}
func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	reasons := []string{}
	if s.auditError() != nil {
		reasons = append(reasons, "audit persistence degraded")
	}
	if s.dbErr != nil {
		reasons = append(reasons, "database unavailable")
	} else if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") != "" {
		if s.db == nil || !s.migrationsOK {
			reasons = append(reasons, "database migrations not ready")
		} else if err := s.db.PingContext(r.Context()); err != nil {
			reasons = append(reasons, "database ping failed")
		}
	}
	probe, err := os.CreateTemp(s.cfg.Workspace, ".ready-*")
	if err != nil {
		reasons = append(reasons, "workspace is not writable")
	} else {
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
	}
	if len(reasons) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "reasons": reasons})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "storage": storageBackend()})
}
func (s *Server) workspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	items, _ := s.listExperiments()
	knowledge := s.readKnowledge()
	counts := map[string]int{}
	for _, x := range items {
		counts[x.Status]++
	}
	writeJSON(w, 200, map[string]any{"generated_at": now(), "workspace": s.cfg.Workspace, "mode": "connected", "summary": map[string]any{"experiment_total": len(items), "active_total": counts["queued"] + counts["planned"] + counts["running"], "needs_attention": counts["failed"], "knowledge_total": len(knowledge), "capability_readiness": 0, "toolchain_dependency_gated": 0, "status_counts": counts}, "experiments": items, "capabilities": []any{}, "evidence": []any{}, "knowledge": knowledge, "environment": s.environmentPayload()})
}

func (s *Server) experiments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		x, err := s.listExperiments()
		respond(w, x, err)
	case "POST":
		var p map[string]any
		if readJSON(r, &p) != nil {
			bad(w, "invalid JSON")
			return
		}
		target := strings.TrimSpace(fmt.Sprint(p["target"]))
		resolved, err := s.safePath(target)
		if err != nil {
			bad(w, err.Error())
			return
		}
		if st, err := os.Stat(resolved); err != nil || st.IsDir() {
			bad(w, "目标文件不存在：请上传本地样本，或填写容器工作区内的文件路径")
			return
		}
		id := newID()
		t := now()
		mode := fmt.Sprint(p["mode"])
		opts := map[string]any{}
		if mode == "pe-reconstruction" {
			opts["reconstruct"] = true
		}
		if mode == "gui-evidence" {
			opts["gui"] = true
			opts["gui_visual"] = true
		}
		requestedAsset := strings.TrimSpace(fmt.Sprint(p["requested_asset"]))
		if requestedAsset != "" && requestedAsset != "<nil>" {
			opts["requested_asset"] = requestedAsset
			lower := strings.ToLower(requestedAsset)
			if strings.Contains(lower, "ghidra") || strings.Contains(lower, "decompil") {
				opts["decompile"] = true
				opts["reconstruct"] = true
			}
			if strings.Contains(lower, "gui") || strings.Contains(lower, "xaml") {
				opts["gui"] = true
				opts["reconstruct_gui"] = true
			}
		}
		x := Experiment{
			Schema: 1, SchemaVersion: 1, ID: id, Sample: resolved, Name: filepath.Base(resolved), Status: "queued",
			CreatedAt: t, UpdatedAt: t, Options: opts,
			Metadata:  map[string]any{"source": "go-web", "execution_boundary": "plan-only", "requires_confirmation": true},
			History:   []map[string]any{{"timestamp": t, "status": "queued", "detail": "created"}},
			Artifacts: []map[string]any{}, Reconstruction: reconstructionState(ReconstructionState{}),
		}
		if requestedAsset != "" && requestedAsset != "<nil>" {
			x.Metadata["requested_asset"] = requestedAsset
		}
		if provider := strings.TrimSpace(fmt.Sprint(p["provider"])); provider != "" && provider != "<nil>" {
			x.Metadata["provider"] = provider
		}
		err = s.saveExperiment(x)
		if err == nil {
			s.appendEvent(id, "queued", "queued", "任务已进入队列", nil)
		}
		if err != nil {
			respond(w, nil, err)
			return
		}
		writeJSON(w, 201, map[string]any{"experiment": x, "executed": false})
	default:
		method(w)
	}
}
func (s *Server) experiment(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/experiments/"), "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		bad(w, "experiment id required")
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == "GET" {
		x, err := s.loadExperiment(id)
		if err == nil && x.Status == "completed" {
			x.Summary = s.artifactSummary(filepath.Join(s.cfg.Workspace, "experiments", id, "analysis"))
		}
		if err == nil && x.Reconstruction.Stage == "" {
			x.Reconstruction = s.deriveLegacyReconstruction(x)
		}
		respond(w, x, err)
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == "GET" {
		if _, err := s.loadExperiment(id); err != nil {
			respond(w, nil, err)
			return
		}
		events, _ := s.events(id)
		if r.URL.Query().Get("raw") != "1" {
			events = withoutRawOutput(events)
		}
		writeJSON(w, 200, map[string]any{"events": events, "count": len(events)})
		return
	}
	if len(parts) == 2 && parts[1] == "stream" && r.Method == "GET" {
		if _, err := s.loadExperiment(id); err != nil {
			respond(w, nil, err)
			return
		}
		s.eventStream(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "source" && r.Method == http.MethodGet {
		s.sourceProject(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "source" && parts[2] == "file" && r.Method == http.MethodPut {
		s.sourceFile(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "source" && parts[2] == "archive" && r.Method == http.MethodGet {
		s.sourceArchive(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "patches" {
		s.patchWorkbench(w, r, id, parts[2:])
		return
	}
	if len(parts) == 2 && parts[1] == "runtime-marks" {
		s.runtimeMarks(w, r, id)
		return
	}
	if len(parts) != 2 || r.Method != "POST" {
		method(w)
		return
	}
	switch parts[1] {
	case "execute":
		var p map[string]any
		_ = readJSON(r, &p)
		if fmt.Sprint(p["confirmation"]) != confirmation {
			writeJSON(w, 403, map[string]any{"error": "explicit confirmation required"})
			return
		}
		x, err := s.startConfirmed(id, r)
		respond(w, map[string]any{"experiment": x, "running": err == nil}, err)
	case "cancel":
		x, err := s.cancelAudited(id, r, s.authenticate(r))
		respond(w, map[string]any{"experiment": x}, err)
	case "retry":
		x, err := s.retryAudited(id, r, s.authenticate(r))
		respond(w, map[string]any{"experiment": x, "retry_of": id}, err)
	case "build":
		var p map[string]any
		_ = readJSON(r, &p)
		if fmt.Sprint(p["confirmation"]) != "BUILD_RECONSTRUCTED_SOURCE" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "重新构建需要显式确认"})
			return
		}
		s.buildSourceProject(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) executionActor(r *http.Request) (*identity, error) {
	who := s.authenticate(r)
	if who == nil && s.cfg.Token == "" {
		who = &identity{Subject: "local-anonymous", Role: "local", Workspace: s.cfg.Workspace, Source: "local"}
	}
	if who == nil {
		return nil, errors.New("confirmation actor unavailable")
	}
	return who, nil
}

func (s *Server) confirmedRunningExperiment(x Experiment, who *identity) (Experiment, map[string]any) {
	confirmedAt := now()
	audit := map[string]any{"actor": who.Subject, "role": who.Role, "timestamp": confirmedAt, "source": who.Source}
	if x.Metadata == nil {
		x.Metadata = map[string]any{}
	}
	x.Metadata["execution_confirmation"] = audit
	x = s.status(x, "running", map[string]any{"source": "go-worker", "confirmation": audit})
	return x, map[string]any{"subject": who.Subject, "role": who.Role, "confirmed_at": confirmedAt}
}

func (s *Server) runtimeMarks(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.loadExperiment(id); err != nil {
		respond(w, nil, err)
		return
	}
	root := filepath.Join(s.cfg.Workspace, "experiments", id, "runtime-marks")
	indexPath := filepath.Join(root, "index.json")
	var records []map[string]any
	_ = readFileJSON(indexPath, &records)
	if r.Method == http.MethodGet {
		if records == nil {
			records = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": records})
		return
	}
	if r.Method != http.MethodPost {
		method(w)
		return
	}
	var payload struct {
		Image string           `json:"image"`
		Marks []map[string]any `json:"marks"`
		Title string           `json:"title"`
	}
	if readJSON(r, &payload) != nil || len(payload.Marks) == 0 || !strings.HasPrefix(payload.Image, "data:image/png;base64,") {
		bad(w, "请先捕获程序窗口并至少标记一个区域")
		return
	}
	imageBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(payload.Image, "data:image/png;base64,"))
	if err != nil || len(imageBytes) == 0 || len(imageBytes) > 20<<20 {
		bad(w, "运行画面无效或超过 20MB")
		return
	}
	recordID := newID()
	_ = os.MkdirAll(root, 0700)
	imagePath := filepath.Join(root, recordID+".png")
	if err = os.WriteFile(imagePath, imageBytes, 0600); err != nil {
		respond(w, nil, err)
		return
	}
	record := map[string]any{"id": recordID, "title": payload.Title, "created_at": now(), "image": relativeTo(s.cfg.Workspace, imagePath), "marks": payload.Marks}
	records = append([]map[string]any{record}, records...)
	if err = writeFileJSON(indexPath, records); err != nil {
		respond(w, nil, err)
		return
	}
	s.appendEvent(id, "runtime_mark_saved", "completed", "已保存程序运行画面与手动框选标注", map[string]any{"record_id": recordID, "mark_count": len(payload.Marks), "image": record["image"]})
	writeJSON(w, http.StatusCreated, record)
}

func (s *Server) patchWorkbench(w http.ResponseWriter, r *http.Request, id string, actionParts []string) {
	experiment, err := s.loadExperiment(id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if len(actionParts) == 0 && r.Method == http.MethodGet {
		var records []PatchRecord
		_ = readFileJSON(filepath.Join(s.patchRoot(id), "index.json"), &records)
		if records == nil {
			records = []PatchRecord{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"patches": records, "target": relativeTo(s.cfg.Workspace, experiment.Sample), "apply_confirmation": "APPLY_AUTHORIZED_PATCH", "rollback_confirmation": "ROLLBACK_AUTHORIZED_PATCH"})
		return
	}
	if len(actionParts) != 1 || r.Method != http.MethodPost {
		method(w)
		return
	}
	if actionParts[0] == "ai-plan" || actionParts[0] == "ai-apply" || actionParts[0] == "ai-rollback" {
		s.aiPatch(w, r, id, actionParts[0])
		return
	}
	var payload map[string]any
	if readJSON(r, &payload) != nil {
		bad(w, "无效的定点修改请求")
		return
	}
	action := actionParts[0]
	if action == "inspect" {
		target, targetErr := s.patchTarget(experiment, payload)
		if targetErr != nil {
			bad(w, targetErr.Error())
			return
		}
		result, bridgeErr := s.pythonPatch(map[string]any{"action": "inspect", "target": target, "offset": payload["offset"], "length": payload["length"]})
		respond(w, result, bridgeErr)
		return
	}
	if action == "plan" {
		target, targetErr := s.patchTarget(experiment, payload)
		if targetErr != nil {
			bad(w, targetErr.Error())
			return
		}
		offset, parseErr := parseOffset(payload["offset"])
		if parseErr != nil {
			bad(w, parseErr.Error())
			return
		}
		expected := compactHex(fmt.Sprint(payload["expected_hex"]))
		replacement := compactHex(fmt.Sprint(payload["replacement_hex"]))
		if expected == "" || len(expected) != len(replacement) || len(expected)%2 != 0 {
			bad(w, "原始字节和替换字节必须是等长十六进制数据")
			return
		}
		inspection, inspectErr := s.pythonPatch(map[string]any{"action": "inspect", "target": target, "offset": offset, "length": len(expected) / 2})
		if inspectErr != nil || !strings.EqualFold(fmt.Sprint(inspection["expected_hex"]), expected) {
			bad(w, "目标位置的预映像字节不匹配，请重新读取证据")
			return
		}
		patchID := newID()
		root := filepath.Join(s.patchRoot(id), patchID)
		_ = os.MkdirAll(root, 0700)
		plan := map[string]any{"schema_version": 1, "target_sha256": inspection["target_sha256"], "strategy": "authorized_point_patch", "operations": []any{map[string]any{"id": "point-change", "kind": "replace_offset", "offset": offset, "expected": expected, "replacement": replacement}}}
		planPath := filepath.Join(root, "plan.json")
		if err = writeFileJSON(planPath, plan); err != nil {
			respond(w, nil, err)
			return
		}
		output := filepath.Join(root, "patched-"+filepath.Base(target))
		artifacts := filepath.Join(root, "audit")
		result, bridgeErr := s.pythonPatch(map[string]any{"action": "plan", "target": target, "plan": plan, "output": output, "artifact_dir": artifacts})
		record := PatchRecord{ID: patchID, ExperimentID: id, Target: relativeTo(s.cfg.Workspace, target), Status: fmt.Sprint(result["status"]), CreatedAt: now(), UpdatedAt: now(), Offset: int64(offset), Length: int64(len(expected) / 2), ExpectedHex: expected, ReplacementHex: replacement, SourceSHA256: fmt.Sprint(inspection["target_sha256"]), Output: relativeTo(s.cfg.Workspace, output), ArtifactDir: relativeTo(s.cfg.Workspace, artifacts)}
		if bridgeErr != nil {
			record.Status = "failed"
			record.Error = bridgeErr.Error()
		}
		s.savePatchRecord(id, record)
		s.appendEvent(id, "patch_planned", record.Status, "定点修改计划已完成预验证", map[string]any{"patch_id": patchID, "offset": fmt.Sprintf("0x%X", offset)})
		writeJSON(w, http.StatusOK, map[string]any{"patch": record, "validation": result, "plan": plan})
		return
	}
	patchID := strings.TrimSpace(fmt.Sprint(payload["patch_id"]))
	record, recordErr := s.loadPatchRecord(id, patchID)
	if recordErr != nil {
		bad(w, "定点修改记录不存在")
		return
	}
	root := filepath.Join(s.patchRoot(id), patchID)
	target, _ := s.safePath(record.Target)
	switch action {
	case "apply":
		if fmt.Sprint(payload["confirmation"]) != "APPLY_AUTHORIZED_PATCH" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "执行定点修改需要显式确认"})
			return
		}
		var plan map[string]any
		if readFileJSON(filepath.Join(root, "plan.json"), &plan) != nil {
			bad(w, "修改计划不可读")
			return
		}
		result, callErr := s.pythonPatch(map[string]any{"action": "apply", "target": target, "plan": plan, "output": filepath.Join(s.cfg.Workspace, filepath.FromSlash(record.Output)), "artifact_dir": filepath.Join(s.cfg.Workspace, filepath.FromSlash(record.ArtifactDir))})
		if callErr != nil {
			record.Status = "failed"
			record.Error = callErr.Error()
		} else {
			record.Status = "applied"
			if data, ok := result["data"].(map[string]any); ok {
				record.PatchedSHA256 = fmt.Sprint(data["patched_sha256"])
			}
		}
		record.UpdatedAt = now()
		s.savePatchRecord(id, record)
		s.appendEvent(id, "patch_applied", record.Status, "定点修改已写入独立副本", map[string]any{"patch_id": patchID})
		writeJSON(w, http.StatusOK, map[string]any{"patch": record, "result": result})
	case "verify":
		patched, pathErr := s.safePath(record.Output)
		if pathErr != nil {
			bad(w, pathErr.Error())
			return
		}
		result, callErr := s.pythonPatch(map[string]any{"action": "verify", "target": patched, "sha256": record.PatchedSHA256})
		respond(w, result, callErr)
	case "rollback":
		if fmt.Sprint(payload["confirmation"]) != "ROLLBACK_AUTHORIZED_PATCH" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "回滚需要显式确认"})
			return
		}
		patched, _ := s.safePath(record.Output)
		rollbackPath := filepath.Join(s.cfg.Workspace, filepath.FromSlash(record.ArtifactDir), "rollback.json")
		restored := filepath.Join(root, "restored-"+filepath.Base(target))
		result, callErr := s.pythonPatch(map[string]any{"action": "rollback", "patched": patched, "rollback": rollbackPath, "output": restored, "artifact_dir": filepath.Join(root, "rollback-audit")})
		if callErr != nil {
			record.Status = "rollback_failed"
			record.Error = callErr.Error()
		} else {
			record.Status = "rolled_back"
			record.Error = ""
		}
		record.UpdatedAt = now()
		s.savePatchRecord(id, record)
		s.appendEvent(id, "patch_rolled_back", record.Status, "已生成并验证回滚副本", map[string]any{"patch_id": patchID, "restored": relativeTo(s.cfg.Workspace, restored)})
		writeJSON(w, http.StatusOK, map[string]any{"patch": record, "result": result, "restored": relativeTo(s.cfg.Workspace, restored)})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) patchRoot(id string) string {
	return filepath.Join(s.cfg.Workspace, "experiments", id, "patches")
}
func (s *Server) patchTarget(experiment Experiment, payload map[string]any) (string, error) {
	raw := strings.TrimSpace(fmt.Sprint(payload["target"]))
	if raw == "" || raw == "<nil>" {
		return experiment.Sample, nil
	}
	path, err := s.safePath(raw)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return "", errors.New("修改目标文件不存在")
	}
	return path, nil
}
func parseOffset(value any) (int, error) {
	raw := strings.TrimSpace(fmt.Sprint(value))
	parsed, err := strconv.ParseInt(raw, 0, 64)
	if err != nil || parsed < 0 {
		return 0, errors.New("偏移必须是非负十进制或 0x 十六进制数")
	}
	return int(parsed), nil
}
func compactHex(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(value), "0x")), ""))
}
func (s *Server) pythonPatch(payload map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	input, _ := json.Marshal(payload)
	cmd := exec.CommandContext(ctx, s.cfg.Python, "-m", "reverse_analyzer.web_patch_bridge")
	cmd.Dir = s.cfg.Workspace
	cmd.Stdin = bytes.NewReader(input)
	output, runErr := cmd.CombinedOutput()
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("补丁引擎输出无效: %s", strings.TrimSpace(string(output)))
	}
	if runErr != nil || fmt.Sprint(result["status"]) == "failed" {
		return result, errors.New(fmt.Sprint(result["error"]))
	}
	return result, nil
}
func (s *Server) savePatchRecord(id string, record PatchRecord) {
	path := filepath.Join(s.patchRoot(id), "index.json")
	var records []PatchRecord
	_ = readFileJSON(path, &records)
	found := false
	for i := range records {
		if records[i].ID == record.ID {
			records[i] = record
			found = true
		}
	}
	if !found {
		records = append([]PatchRecord{record}, records...)
	}
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = writeFileJSON(path, records)
}
func (s *Server) loadPatchRecord(id, patchID string) (PatchRecord, error) {
	if len(patchID) != 32 {
		return PatchRecord{}, errors.New("invalid patch id")
	}
	var records []PatchRecord
	if err := readFileJSON(filepath.Join(s.patchRoot(id), "index.json"), &records); err != nil {
		return PatchRecord{}, err
	}
	for _, record := range records {
		if record.ID == patchID {
			return record, nil
		}
	}
	return PatchRecord{}, os.ErrNotExist
}

func (s *Server) sourceProject(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	files := []map[string]any{}
	_ = filepath.Walk(project, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || strings.Contains(filepath.ToSlash(path), "/.build/") || len(files) >= 5000 {
			return nil
		}
		rel, _ := filepath.Rel(project, path)
		if filepath.ToSlash(rel) == "SOURCE_TREE.json" || filepath.ToSlash(rel) == "BUILD_STATUS.json" {
			return nil
		}
		if rel == "." {
			return nil
		}
		files = append(files, map[string]any{"path": filepath.ToSlash(rel), "size": info.Size(), "editable": !info.IsDir() && sourceEditable(rel), "directory": info.IsDir()})
		return nil
	})
	payload := map[string]any{"project_root": relativeTo(s.cfg.Workspace, project), "files": files, "build_system": "cmake", "confirmation": "BUILD_RECONSTRUCTED_SOURCE"}
	if requested := strings.TrimSpace(r.URL.Query().Get("path")); requested != "" {
		path, pathErr := safeProjectFile(project, requested)
		if pathErr != nil {
			bad(w, pathErr.Error())
			return
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil || len(content) > 2<<20 {
			bad(w, "源码文件无法读取或超过 2MB")
			return
		}
		payload["selected_path"] = filepath.ToSlash(requested)
		payload["content"] = string(content)
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) sourceFile(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	var payload struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if readJSON(r, &payload) != nil || !sourceEditable(payload.Path) || len(payload.Content) > 2<<20 {
		bad(w, "仅允许保存 2MB 以内的源码、CMake 或说明文件")
		return
	}
	path, err := safeProjectFile(project, payload.Path)
	if err != nil {
		bad(w, err.Error())
		return
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		bad(w, "不允许编辑符号链接")
		return
	}
	if err = os.WriteFile(path, []byte(payload.Content), 0600); err != nil {
		respond(w, nil, err)
		return
	}
	s.appendEvent(id, "source_saved", "completed", "已保存重构源码 "+filepath.ToSlash(payload.Path), nil)
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(payload.Path), "size": len(payload.Content), "saved": true})
}

func (s *Server) sourceArchive(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="reconstructed-%s.zip"`, id[:8]))
	archive := zip.NewWriter(w)
	defer archive.Close()
	manifest := []map[string]any{}
	_ = filepath.Walk(project, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || strings.Contains(filepath.ToSlash(path), "/.build/") {
			return nil
		}
		rel, _ := filepath.Rel(project, path)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		manifest = append(manifest, map[string]any{"path": filepath.ToSlash(rel), "size": info.Size(), "sha256": sha256Hex(data), "editable": sourceEditable(rel)})
		entry, createErr := archive.Create(filepath.ToSlash(rel))
		if createErr != nil {
			return createErr
		}
		_, copyErr := entry.Write(data)
		return copyErr
	})
	if entry, createErr := archive.Create("SOURCE_TREE.json"); createErr == nil {
		payload, _ := json.MarshalIndent(map[string]any{"schema_version": 1, "project_root": filepath.Base(project), "generated_at": now(), "files": manifest}, "", "  ")
		_, _ = entry.Write(append(payload, '\n'))
	}
	if experiment, loadErr := s.loadExperiment(id); loadErr == nil {
		if entry, createErr := archive.Create("BUILD_STATUS.json"); createErr == nil {
			payload, _ := json.MarshalIndent(map[string]any{"schema_version": 1, "experiment_id": id, "reconstruction": experiment.Reconstruction}, "", "  ")
			_, _ = entry.Write(append(payload, '\n'))
		}
	}
}

func (s *Server) buildSourceProject(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	if _, err = exec.LookPath("cmake"); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "运行环境缺少 cmake"})
		return
	}
	isolated, isolation := buildIsolation()
	if !isolated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "dependency-gated", "error": "真实构建必须在容器或明确配置的隔离运行时中执行", "isolation": isolation})
		return
	}
	buildDir := filepath.Join(project, ".build")
	_ = os.MkdirAll(buildDir, 0755)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	output := &limitedWriter{remaining: 2 << 20}
	s.appendEvent(id, "build_started", "running", "开始构建重构源码工程", map[string]any{"isolated": true, "isolation": isolation})
	for _, args := range [][]string{{"-S", project, "-B", buildDir}, {"--build", buildDir, "--config", "Release"}} {
		cmd := exec.CommandContext(ctx, "cmake", args...)
		cmd.Dir = project
		cmd.Stdout, cmd.Stderr = output, output
		if err = cmd.Run(); err != nil {
			break
		}
	}
	logPath := filepath.Join(project, "build-output.log")
	_ = os.WriteFile(logPath, output.buf.Bytes(), 0600)
	if err != nil {
		s.appendEvent(id, "build_failed", "failed", "重构工程构建失败", map[string]any{"log": relativeTo(s.cfg.Workspace, logPath)})
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"status": "failed", "error": err.Error(), "output": output.String(), "log": relativeTo(s.cfg.Workspace, logPath)})
		return
	}
	experiment, _ := s.loadExperiment(id)
	experiment.Artifacts = s.collectArtifacts(filepath.Join(s.cfg.Workspace, "experiments", id, "analysis"))
	experiment.Reconstruction.BuildPassed = true
	experiment.Reconstruction.SourceGenerated = true
	experiment.Reconstruction.Iteration++
	experiment.Reconstruction = reconstructionState(experiment.Reconstruction)
	experiment.UpdatedAt = now()
	_ = s.saveExperiment(experiment)
	s.appendEvent(id, "build_completed", "completed", "重构工程构建完成", map[string]any{"build_dir": relativeTo(s.cfg.Workspace, buildDir), "log": relativeTo(s.cfg.Workspace, logPath), "isolated": true, "isolation": isolation})
	writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "output": output.String(), "build_dir": relativeTo(s.cfg.Workspace, buildDir), "log": relativeTo(s.cfg.Workspace, logPath), "isolated": true, "isolation": isolation})
}

func buildIsolation() (bool, string) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true, "container"
	}
	if strings.EqualFold(os.Getenv("REVERSE_ANALYZER_ALLOW_HOST_BUILD"), "1") || strings.EqualFold(os.Getenv("REVERSE_ANALYZER_ALLOW_HOST_BUILD"), "true") {
		return true, "explicit-host-test"
	}
	return false, "host"
}

func (s *Server) findSourceProject(id string) (string, error) {
	if _, err := s.loadExperiment(id); err != nil {
		return "", err
	}
	root := filepath.Join(s.cfg.Workspace, "experiments", id, "analysis")
	project := ""
	preferred, _ := filepath.Glob(filepath.Join(root, "reconstructed_archive_*", "CMakeLists.txt"))
	if len(preferred) > 0 {
		sort.Slice(preferred, func(i, j int) bool {
			left, _ := os.Stat(preferred[i])
			right, _ := os.Stat(preferred[j])
			return left != nil && right != nil && left.ModTime().After(right.ModTime())
		})
		project = filepath.Dir(preferred[0])
	}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == "CMakeLists.txt" && project == "" {
			project = filepath.Dir(path)
		}
		return nil
	})
	if project == "" {
		return "", errors.New("该任务没有生成可编辑源码工程")
	}
	return project, nil
}

func safeProjectFile(project, requested string) (string, error) {
	path := filepath.Join(project, filepath.FromSlash(requested))
	path, _ = filepath.Abs(path)
	rel, err := filepath.Rel(project, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("源码路径超出重构工程")
	}
	return path, nil
}

func sourceEditable(path string) bool {
	name := filepath.Base(path)
	extension := strings.ToLower(filepath.Ext(name))
	return name == "CMakeLists.txt" || map[string]bool{".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true, ".md": true, ".py": true, ".java": true, ".kt": true, ".smali": true, ".xml": true, ".json": true, ".js": true, ".ts": true, ".html": true, ".css": true, ".gradle": true, ".properties": true, ".txt": true}[extension]
}

func relativeTo(root, path string) string {
	rel, _ := filepath.Rel(root, path)
	return filepath.ToSlash(rel)
}

type limitedWriter struct {
	buf       bytes.Buffer
	remaining int64
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	original := len(p)
	if int64(len(p)) > w.remaining {
		p = p[:max(0, int(w.remaining))]
		w.truncated = true
	}
	_, _ = w.buf.Write(p)
	w.remaining -= int64(len(p))
	return original, nil
}

func (w *limitedWriter) String() string {
	if w.truncated {
		return w.buf.String() + "\n[输出已截断，完整信息见构建日志]"
	}
	return w.buf.String()
}

func (s *Server) flowTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	writeJSON(w, 200, map[string]any{"templates": []map[string]any{
		{"id": "evidence-first", "name": "证据优先扫描", "mode": "evidence-first", "stages": []string{"静态识别", "证据提取", "知识召回", "报告"}},
		{"id": "pe-reconstruction", "name": "PE 深度还原", "mode": "pe-reconstruction", "stages": []string{"静态分析", "反编译", "语义 IR", "源码生成", "等价验证"}},
		{"id": "protocol-review", "name": "协议捕获审查", "mode": "protocol-review", "stages": []string{"捕获导入", "流重组", "格式推断", "重放验证"}},
		{"id": "gui-evidence", "name": "GUI 证据流水线", "mode": "gui-evidence", "stages": []string{"资源提取", "运行时探测", "视觉解析", "状态机", "重构验证"}},
	}})
}

func (s *Server) eventStream(w http.ResponseWriter, r *http.Request, id string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	last, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := s.events(id)
		if err != nil {
			return
		}
		for _, event := range events {
			if event.Sequence <= last {
				continue
			}
			last = event.Sequence
			if event.Type == "output" {
				continue
			}
			payload, _ := json.Marshal(event)
			fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Sequence, event.Type, payload)
			flusher.Flush()
		}
		x, err := s.loadExperiment(id)
		if err == nil && x.Status != "queued" && x.Status != "planned" && x.Status != "running" {
			fmt.Fprint(w, "event: close\ndata: {}\n\n")
			flusher.Flush()
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) startConfirmed(id string, r *http.Request) (Experiment, error) {
	who, err := s.executionActor(r)
	if err != nil {
		return Experiment{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	var x Experiment
	var eventData map[string]any
	if s.db != nil {
		tx, txErr := s.db.BeginTx(r.Context(), nil)
		if txErr != nil {
			cancel()
			return x, txErr
		}
		defer tx.Rollback()
		if txErr = s.setAuditTransactionContext(tx, r, who, "experiment.execute"); txErr != nil {
			cancel()
			return x, txErr
		}
		var payload []byte
		if txErr = tx.QueryRowContext(r.Context(), `SELECT payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&payload); txErr != nil {
			cancel()
			return x, txErr
		}
		if txErr = json.Unmarshal(payload, &x); txErr != nil {
			cancel()
			return x, txErr
		}
		if x.Status != "queued" && x.Status != "planned" {
			cancel()
			return x, errors.New("only queued or planned jobs can run")
		}
		x, eventData = s.confirmedRunningExperiment(x, who)
		payload, txErr = json.Marshal(x)
		if txErr != nil {
			cancel()
			return x, txErr
		}
		result, txErr := tx.ExecContext(r.Context(), `UPDATE experiments SET status=$1,updated_at=$2,payload=$3::jsonb WHERE id=$4 AND workspace_id=$5 AND status IN ('queued','planned')`, x.Status, x.UpdatedAt, string(payload), id, s.cfg.Workspace)
		if txErr != nil {
			cancel()
			return x, txErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil || rows != 1 {
			cancel()
			return x, errors.New("job execution was already claimed")
		}
		if _, txErr = insertEventTx(tx, id, "execution_confirmed", "completed", "人工确认已记录", eventData); txErr != nil {
			cancel()
			return x, txErr
		}
		if _, txErr = insertEventTx(tx, id, "started", "running", "任务执行器已启动", nil); txErr != nil {
			cancel()
			return x, txErr
		}
		if txErr = tx.Commit(); txErr != nil {
			cancel()
			return x, txErr
		}
		s.mu.Lock()
		if _, exists := s.running[id]; exists {
			s.mu.Unlock()
			cancel()
			return x, errors.New("job execution was already claimed")
		}
		s.running[id] = cancel
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		if _, exists := s.running[id]; exists {
			s.mu.Unlock()
			cancel()
			return x, errors.New("job execution was already claimed")
		}
		err = readFileJSON(s.experimentPath(id), &x)
		if err != nil {
			s.mu.Unlock()
			cancel()
			return x, err
		}
		if x.Status != "queued" && x.Status != "planned" {
			s.mu.Unlock()
			cancel()
			return x, errors.New("only queued or planned jobs can run")
		}
		x, eventData = s.confirmedRunningExperiment(x, who)
		err = writeFileJSON(s.experimentPath(id), x)
		if err != nil {
			s.mu.Unlock()
			cancel()
			return x, err
		}
		s.running[id] = cancel
		s.mu.Unlock()
	}
	if s.db == nil {
		s.appendEvent(id, "execution_confirmed", "completed", "人工确认已记录", eventData)
		s.appendEvent(id, "started", "running", "任务执行器已启动", nil)
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		s.run(ctx, x)
	}()
	return x, nil
}
func (s *Server) run(ctx context.Context, x Experiment) {
	out := filepath.Join(s.cfg.Workspace, "experiments", x.ID, "analysis")
	_ = os.MkdirAll(out, 0755)
	args := analysisArgs(x, out)
	requested := fmt.Sprint(x.Metadata["provider"])
	if requested == "<nil>" {
		requested = ""
	}
	selected, fallback := s.selectProvider(requested)
	runtimeProvider := selected.Name
	processEnv := []string{"REVERSE_ANALYZER_PROVIDER=" + runtimeProvider, "REVERSE_ANALYZER_WORKER_NETWORK=none"}
	envNames := []string{"REVERSE_ANALYZER_PROVIDER", "REVERSE_ANALYZER_WORKER_NETWORK"}
	workerNetwork := "none"
	var brokerCancel context.CancelFunc
	if selected.Kind == "openai-compatible" {
		if s.cfg.SandboxRuntime != "docker" && s.cfg.SandboxRuntime != "podman" {
			err := errors.New("external model providers require a Docker or Podman worker so credentials remain outside the worker")
			latest, loadErr := s.loadExperiment(x.ID)
			if loadErr == nil {
				latest = s.status(latest, "failed", err.Error())
				latest.Error = err.Error()
				_ = s.saveExperiment(latest)
			}
			return
		}
		runtimeProvider = "openai_compatible"
		brokerRoot := filepath.Join(out, "provider-broker")
		broker, brokerErr := newProviderBroker(brokerRoot, selected)
		if brokerErr != nil {
			err := fmt.Errorf("provider broker setup failed: %w", brokerErr)
			latest, loadErr := s.loadExperiment(x.ID)
			if loadErr == nil {
				latest = s.status(latest, "failed", err.Error())
				latest.Error = err.Error()
				_ = s.saveExperiment(latest)
			}
			return
		}
		brokerContext, cancel := context.WithCancel(ctx)
		brokerCancel = cancel
		go broker.run(brokerContext)
		workerBrokerRoot := brokerRoot
		if s.cfg.SandboxRuntime == "docker" || s.cfg.SandboxRuntime == "podman" {
			relativeBroker, relativeErr := filepath.Rel(s.cfg.Workspace, brokerRoot)
			if relativeErr != nil || relativeBroker == ".." || strings.HasPrefix(relativeBroker, ".."+string(filepath.Separator)) {
				cancel()
				return
			}
			workerBrokerRoot = filepath.ToSlash(filepath.Join("/workspace", relativeBroker))
		}
		processEnv = []string{
			"REVERSE_ANALYZER_PROVIDER=" + runtimeProvider,
			"REVERSE_ANALYZER_WORKER_NETWORK=none",
			"REVERSE_ANALYZER_OPENAI_ENABLED=1",
			"OPENAI_MODEL=" + selected.Model,
			"REVERSE_ANALYZER_PROVIDER_BROKER_DIR=" + workerBrokerRoot,
			"REVERSE_ANALYZER_PROVIDER_TIMEOUT=" + env("REVERSE_ANALYZER_PROVIDER_TIMEOUT", "60"),
			"REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS=" + env("REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS", "4096"),
		}
		envNames = []string{"REVERSE_ANALYZER_PROVIDER", "REVERSE_ANALYZER_WORKER_NETWORK", "REVERSE_ANALYZER_OPENAI_ENABLED", "OPENAI_MODEL", "REVERSE_ANALYZER_PROVIDER_BROKER_DIR", "REVERSE_ANALYZER_PROVIDER_TIMEOUT", "REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS"}
		s.appendEvent(x.ID, "provider_broker_started", "running", "模型请求代理已启动，分析 worker 保持无网络", map[string]any{"provider": selected.Name, "model": selected.Model, "worker_network": "none", "broker": true})
	}
	if brokerCancel != nil {
		defer brokerCancel()
	}
	cmd := s.workerCommandWithNetwork(ctx, args, envNames, workerNetwork)
	cmd.Dir = s.cfg.Workspace
	cmd.Env = append(os.Environ(), processEnv...)
	if fallback {
		s.appendEvent(x.ID, "provider_fallback", "running", "请求的 Provider 不可用，已回退到 "+selected.Name, map[string]any{"requested": requested, "selected": selected.Name})
	}
	pipe, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	err := cmd.Start()
	if err == nil {
		progressDone := make(chan struct{})
		startedAt := time.Now()
		s.appendEvent(x.ID, "progress", "running", "分析引擎已启动，正在准备输入", map[string]any{"percent": 28, "estimated": true, "elapsed_seconds": 0})
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for step := 1; ; step++ {
				select {
				case <-progressDone:
					return
				case <-ticker.C:
					seconds := int(time.Since(startedAt).Seconds())
					percent := min(88, 28+step*2)
					s.appendEvent(x.ID, "progress", "running", fmt.Sprintf("分析引擎运行中，已用时 %d 秒", seconds), map[string]any{"percent": percent, "estimated": true, "elapsed_seconds": seconds})
				}
			}
		}()
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		outputPath := filepath.Join(out, "worker-output.json")
		outputFile, outputErr := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		var outputWriter *bufio.Writer
		if outputErr == nil {
			outputWriter = bufio.NewWriterSize(outputFile, 128*1024)
		}
		outputLines := 0
		outputBytes := int64(0)
		for scanner.Scan() {
			line := scanner.Text()
			outputLines++
			outputBytes += int64(len(line) + 1)
			if outputWriter != nil {
				_, _ = outputWriter.WriteString(line + "\n")
			}
		}
		if outputWriter != nil {
			_ = outputWriter.Flush()
			_ = outputFile.Close()
		}
		err = cmd.Wait()
		close(progressDone)
		s.appendEvent(x.ID, "result_summary", "running", fmt.Sprintf("执行日志已归档：%d 行，%s", outputLines, byteSize(outputBytes)), map[string]any{"output_lines": outputLines, "log_bytes": outputBytes, "artifact": filepath.ToSlash(filepath.Join("experiments", x.ID, "analysis", "worker-output.json"))})
	}
	s.mu.Lock()
	delete(s.running, x.ID)
	s.mu.Unlock()
	latest, e := s.loadExperiment(x.ID)
	if e != nil {
		return
	}
	if ctx.Err() == context.DeadlineExceeded {
		latest = s.status(latest, "failed", "worker timeout")
		latest.Error = "analysis timed out"
	} else if err != nil {
		latest = s.status(latest, "failed", err.Error())
		latest.Error = err.Error()
	} else {
		latest = s.status(latest, "completed", "result recorded")
		latest.Artifacts = s.collectArtifacts(out)
		latest.Summary = s.artifactSummary(out)
		latest.Reconstruction.AnalysisComplete = true
		latest.Reconstruction.SourceGenerated = sourceProjectExists(out)
		latest.Reconstruction = reconstructionState(latest.Reconstruction)
	}
	gateObserved := false
	if readiness, found := loadBuildReadiness(out); found {
		gateObserved = true
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["project_readiness"] = readiness
		latest.Reconstruction.StructureComplete, _ = readiness["structure_complete"].(bool)
		latest.Reconstruction.DependenciesLocked, _ = readiness["dependencies_locked"].(bool)
		latest.Reconstruction = reconstructionState(latest.Reconstruction)
		s.appendEvent(x.ID, "project_readiness", "completed", "工程结构与依赖锁定状态已记录", readiness)
	}
	if buildState, found := loadAutomatedBuildResult(out); found {
		gateObserved = true
		exposeArtifactPaths(buildState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["automated_build"] = buildState
		latest.Reconstruction = applyAutomatedBuildState(latest.Reconstruction, buildState)
		latest.Reconstruction = reconstructionState(latest.Reconstruction)
		eventType := "automated_build_" + strings.ReplaceAll(fmt.Sprint(buildState["status"]), "-", "_")
		s.appendEvent(x.ID, eventType, fmt.Sprint(buildState["status"]), "隔离构建结果已记录", buildState)
	}
	if behaviorState, found := loadBehaviorValidationResult(out); found {
		gateObserved = true
		exposeArtifactPaths(behaviorState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["behavior_validation"] = behaviorState
		latest.Reconstruction = applyBehaviorValidationState(latest.Reconstruction, behaviorState)
		eventType := "behavior_" + strings.ReplaceAll(fmt.Sprint(behaviorState["status"]), "-", "_")
		s.appendEvent(x.ID, eventType, fmt.Sprint(behaviorState["status"]), "原程序与重构程序行为对比结果已记录", behaviorState)
	}
	if repairState, found := loadRepairLoopSummary(out, "build"); found {
		exposeArtifactPaths(repairState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["build_repair_loop"] = repairState
		s.appendEvent(x.ID, "build_repair_recorded", fmt.Sprint(repairState["status"]), "编译修复循环已记录", repairState)
	}
	if repairState, found := loadRepairLoopSummary(out, "behavior"); found {
		exposeArtifactPaths(repairState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["behavior_repair_loop"] = repairState
		s.appendEvent(x.ID, "behavior_repair_recorded", fmt.Sprint(repairState["status"]), "行为修复循环已记录", repairState)
	}
	modelState, modelFound := loadModelReconstruction(out)
	if modelFound {
		exposeArtifactPaths(modelState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["model_reconstruction"] = modelState
		status := fmt.Sprint(modelState["status"])
		calls := int64(numberValue(modelState["call_count"]))
		inputTokens := int64(numberValue(modelState["input_tokens"]))
		outputTokens := int64(numberValue(modelState["output_tokens"]))
		failed := status == "failed"
		s.recordProviderUsage(fmt.Sprint(modelState["provider"]), calls, failed, inputTokens, outputTokens)
		eventType := "model_completed"
		if status != "executed" {
			eventType = "model_" + strings.ReplaceAll(status, "-", "_")
			latest.Reconstruction.BlockingReasons = append(latest.Reconstruction.BlockingReasons, map[string]string{"failed": "model_reconstruction_failed", "dependency-gated": "model_provider_not_ready"}[status])
			latest.Reconstruction.CompleteBuildable = false
		}
		s.appendEvent(x.ID, eventType, status, "模型重构阶段已记录", modelState)
	} else {
		s.recordProvider(selected.Name, err != nil || ctx.Err() == context.DeadlineExceeded)
	}
	if gateObserved && !latest.Reconstruction.CompleteBuildable && latest.Status == "completed" {
		latest = s.status(latest, "partial", "reconstruction gates remain incomplete")
	}
	_ = s.saveExperiment(latest)
	s.appendEvent(x.ID, latest.Status, latest.Status, map[string]string{"completed": "分析任务已完成", "partial": "分析已结束，完整构建门禁尚未通过", "failed": "分析任务失败"}[latest.Status], nil)
}

func applyAutomatedBuildState(state ReconstructionState, buildState map[string]any) ReconstructionState {
	if buildState["status"] == "passed" && buildState["isolated"] == true {
		state.BuildPassed = true
		state.Iteration++
	}
	return state
}

func exposeArtifactPaths(value any, artifactRoot, workspaceRoot string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if path, ok := item.(string); ok {
				candidate := filepath.Join(artifactRoot, filepath.FromSlash(path))
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					typed[key] = relativeTo(workspaceRoot, candidate)
				}
				continue
			}
			exposeArtifactPaths(item, artifactRoot, workspaceRoot)
		}
	case []map[string]any:
		for _, item := range typed {
			exposeArtifactPaths(item, artifactRoot, workspaceRoot)
		}
	case []any:
		for _, item := range typed {
			exposeArtifactPaths(item, artifactRoot, workspaceRoot)
		}
	}
}

func loadBehaviorValidationResult(root string) (map[string]any, bool) {
	var payload map[string]any
	artifact, found := trustedDocsArtifact(root, "behavior-validation.json")
	if !found || readBoundedJSON(artifact, maxArtifactPreviewBytes, &payload) != nil || payload == nil {
		return nil, false
	}
	provenance, _ := payload["provenance"].(map[string]any)
	validator, _ := provenance["validator"].(map[string]any)
	archiveValidation, _ := payload["archive_validation"].(map[string]any)
	summary, _ := payload["summary"].(map[string]any)
	comparisonCount, hasSummaryComparisonCount := summary["comparison_count"]
	if !hasSummaryComparisonCount {
		comparisonCount = payload["comparison_count"]
	}
	mismatchCount, hasSummaryMismatchCount := summary["mismatched_comparison_count"]
	if !hasSummaryMismatchCount {
		mismatchCount = payload["mismatch_count"]
	}
	comparisonInteger, comparisonValid := nonnegativeJSONInteger(comparisonCount)
	mismatchInteger, mismatchValid := nonnegativeJSONInteger(mismatchCount)
	schemaVersion, schemaValid := nonnegativeJSONInteger(payload["schema_version"])
	verified := schemaValid && schemaVersion == 1 &&
		payload["status"] == "passed" && payload["behavior_equivalent"] == true &&
		archiveValidation["isolated"] == true && comparisonValid && comparisonInteger > 0 && mismatchValid && mismatchInteger == 0 &&
		validator["real_subprocess"] == true && validator["runner_injected"] == false && validator["shell"] == false
	var platformComparisonCount any
	if comparisonValid {
		platformComparisonCount = comparisonInteger
	}
	var platformMismatchCount any
	if mismatchValid {
		platformMismatchCount = mismatchInteger
	}
	return map[string]any{
		"status":              payload["status"],
		"behavior_equivalent": payload["behavior_equivalent"] == true,
		"strictly_verified":   verified,
		"comparison_count":    platformComparisonCount,
		"mismatch_count":      platformMismatchCount,
		"diagnostics":         payload["diagnostics"],
		"artifact":            relativeTo(root, artifact),
	}, true
}

func loadRepairLoopSummary(root, kind string) (map[string]any, bool) {
	if kind != "build" && kind != "behavior" {
		return nil, false
	}
	name := kind + "-repair-loop.json"
	artifact, found := trustedDocsArtifact(root, name)
	if !found {
		return nil, false
	}
	var payload map[string]any
	if readBoundedJSON(artifact, maxRepairLoopBytes, &payload) != nil || payload == nil {
		return nil, false
	}
	schema, schemaOK := nonnegativeJSONInteger(payload["schema_version"])
	iterationsCompleted, iterationsOK := nonnegativeJSONInteger(payload["iterations_completed"])
	if !schemaOK || schema != 1 || !iterationsOK {
		return nil, false
	}
	status := fmt.Sprint(payload["status"])
	if status != "passed" && status != "failed" && status != "exhausted" && status != "dependency-gated" {
		return nil, false
	}
	projectRoot := filepath.Dir(filepath.Dir(artifact))
	rawIterations, ok := payload["iterations"].([]any)
	if !ok || iterationsCompleted != int64(len(rawIterations)) {
		return nil, false
	}
	rounds := make([]map[string]any, 0, len(rawIterations))
	for index, raw := range rawIterations {
		record, ok := raw.(map[string]any)
		if !ok {
			return nil, false
		}
		iteration, valid := nonnegativeJSONInteger(record["iteration"])
		if !valid || iteration != int64(index+1) {
			return nil, false
		}
		round := map[string]any{
			"iteration": iteration, "status": record["status"], "error": record["error"],
			"diagnostic_bytes":               numberValue(record["diagnostic_bytes"]),
			"attempted_applied_change_count": numberValue(record["attempted_applied_change_count"]),
			"committed_applied_change_count": numberValue(record["committed_applied_change_count"]),
		}
		for _, field := range []string{"diagnostics", "build_before", "build_after", "repair", "behavior_diff", "behavior_before", "behavior_after", "model_repair", "build_result"} {
			value, exists := record[field]
			if !exists || value == nil || value == "" {
				continue
			}
			path, valid := trustedProjectArtifact(root, projectRoot, value)
			if !valid {
				return nil, false
			}
			round[field] = path
		}
		if evidence, exists := record["evidence_refresh"].(map[string]any); exists {
			evidenceSummary := map[string]any{"status": evidence["status"], "error": evidence["error"]}
			if rawArtifacts, ok := evidence["artifacts"].([]any); ok {
				artifacts := make([]string, 0, len(rawArtifacts))
				for _, rawArtifact := range rawArtifacts {
					path, valid := trustedProjectArtifact(root, projectRoot, rawArtifact)
					if !valid {
						return nil, false
					}
					artifacts = append(artifacts, path)
				}
				evidenceSummary["artifacts"] = artifacts
			}
			round["evidence_refresh"] = evidenceSummary
		}
		repairPath, hasRepair := round["repair"].(string)
		if !hasRepair {
			repairPath, hasRepair = round["model_repair"].(string)
		}
		if hasRepair {
			var repair map[string]any
			if readBoundedJSON(filepath.Join(root, filepath.FromSlash(repairPath)), maxRepairLoopBytes, &repair) != nil {
				return nil, false
			}
			changes, _ := repair["applied_changes"].([]any)
			round["model_change_count"] = len(changes)
			round["usage"] = repair["usage"]
		}
		for _, field := range []string{"build_before", "build_after", "build_result"} {
			if path, ok := round[field].(string); ok {
				var build map[string]any
				if readBoundedJSON(filepath.Join(root, filepath.FromSlash(path)), maxArtifactPreviewBytes, &build) == nil {
					round[field+"_status"] = build["status"]
				}
			}
		}
		for _, field := range []string{"behavior_before", "behavior_after"} {
			if path, ok := round[field].(string); ok {
				var behavior map[string]any
				if readBoundedJSON(filepath.Join(root, filepath.FromSlash(path)), maxArtifactPreviewBytes, &behavior) == nil {
					round[field+"_mismatch_count"] = behaviorMismatchCount(behavior)
				}
			}
		}
		rounds = append(rounds, round)
	}
	usage, _ := payload["usage"].(map[string]any)
	return map[string]any{
		"status": status, "passed": payload["passed"] == true,
		"iterations_completed": iterationsCompleted, "usage": usage,
		"attempted_applied_change_count": numberValue(payload["attempted_applied_change_count"]),
		"committed_applied_change_count": numberValue(payload["applied_change_count"]),
		"blocking_reasons":               payload["blocking_reasons"], "iterations": rounds,
		"artifact": relativeTo(root, artifact),
	}, true
}

func behaviorMismatchCount(payload map[string]any) int64 {
	if summary, ok := payload["summary"].(map[string]any); ok {
		if count, valid := nonnegativeJSONInteger(summary["mismatched_comparison_count"]); valid {
			return count
		}
	}
	if comparisons, ok := payload["comparisons"].([]any); ok {
		var count int64
		for _, item := range comparisons {
			if comparison, ok := item.(map[string]any); ok && comparison["matched"] == false {
				count++
			}
		}
		return count
	}
	return 0
}

func trustedDocsArtifact(root, name string) (string, bool) {
	candidates := []string{
		filepath.Join(root, "archive-workspace-v3", "project", "docs", name),
		filepath.Join(root, "project", "docs", name),
		filepath.Join(root, "docs", name),
	}
	reconstructed, err := filepath.Glob(filepath.Join(root, "reconstructed_archive_*", "docs", name))
	if err != nil || len(reconstructed) > 1 {
		return "", false
	}
	if len(reconstructed) == 1 {
		candidates = append(candidates, reconstructed[0])
	}
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
		resolvedDocs, docsErr := filepath.EvalSymlinks(filepath.Dir(candidate))
		resolvedCandidate, candidateErr := filepath.EvalSymlinks(candidate)
		resolvedRoot, rootErr := filepath.EvalSymlinks(root)
		expectedRelative, expectedErr := filepath.Rel(root, candidate)
		actualRelative, actualErr := filepath.Rel(resolvedRoot, resolvedCandidate)
		if docsErr != nil || candidateErr != nil || rootErr != nil || expectedErr != nil || actualErr != nil || filepath.Dir(resolvedCandidate) != resolvedDocs || actualRelative != expectedRelative {
			return "", false
		}
		return resolvedCandidate, true
	}
	return "", false
}

func trustedProjectArtifact(root, projectRoot string, value any) (string, bool) {
	raw, ok := value.(string)
	if !ok || raw == "" || filepath.IsAbs(raw) {
		return "", false
	}
	candidate := filepath.Clean(filepath.Join(projectRoot, filepath.FromSlash(raw)))
	rel, err := filepath.Rel(projectRoot, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return "", false
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(projectRoot)
	resolvedCandidate, candidateErr := filepath.EvalSymlinks(candidate)
	if rootErr != nil || candidateErr != nil {
		return "", false
	}
	resolvedRelative, resolvedErr := filepath.Rel(resolvedRoot, resolvedCandidate)
	if resolvedErr != nil || resolvedRelative == ".." || strings.HasPrefix(resolvedRelative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relativeTo(root, candidate), true
}

func readBoundedJSON(path string, limit int64, payload any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > limit {
		return errors.New("JSON artifact exceeds size limit")
	}
	decoder := json.NewDecoder(io.LimitReader(file, limit+1))
	decoder.UseNumber()
	if err = decoder.Decode(payload); err != nil {
		return err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON artifact contains trailing data")
	}
	return nil
}

func nonnegativeJSONInteger(value any) (int64, bool) {
	var number json.Number
	switch typed := value.(type) {
	case json.Number:
		number = typed
	case int:
		if typed < 0 {
			return 0, false
		}
		return int64(typed), true
	case int64:
		if typed < 0 {
			return 0, false
		}
		return typed, true
	case float64:
		if typed < 0 || typed > math.MaxInt64 || math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return parsed, true
}

func applyBehaviorValidationState(state ReconstructionState, behaviorState map[string]any) ReconstructionState {
	state.BehaviorPassed = behaviorState["strictly_verified"] == true
	return reconstructionState(state)
}

func loadAutomatedBuildResult(root string) (map[string]any, bool) {
	var payload map[string]any
	artifact, found := trustedDocsArtifact(root, "build-result.json")
	if !found || readBoundedJSON(artifact, maxArtifactPreviewBytes, &payload) != nil || payload == nil {
		return nil, false
	}
	schema, schemaOK := nonnegativeJSONInteger(payload["schema_version"])
	stages, stagesOK := payload["stages"].([]any)
	status := fmt.Sprint(payload["status"])
	isolated, isolatedOK := payload["isolated"].(bool)
	buildPassed, buildPassedOK := payload["build_passed"].(bool)
	_, buildPassedPresent := payload["build_passed"]
	artifactCount, countOK := nonnegativeJSONInteger(payload["artifact_count"])
	artifacts, artifactsOK := payload["artifacts"].([]any)
	if !schemaOK || schema != 1 || !stagesOK || !isolatedOK || !countOK || !artifactsOK || artifactCount != int64(len(artifacts)) ||
		(status != "passed" && status != "failed" && status != "timed_out" && status != "error" && status != "dependency-gated") {
		return nil, false
	}
	if (status == "passed" && (!buildPassedOK || !buildPassed)) || (status != "passed" && ((!buildPassedOK && buildPassedPresent) || buildPassed)) {
		return nil, false
	}
	seenStages := map[string]bool{}
	stageNames := make([]string, 0, len(stages))
	for _, rawStage := range stages {
		stage, ok := rawStage.(map[string]any)
		name, nameOK := stage["name"].(string)
		stageStatus, statusOK := stage["status"].(string)
		if !ok || !nameOK || !statusOK || (name != "configure" && name != "build") || seenStages[name] ||
			(stageStatus != "passed" && stageStatus != "failed" && stageStatus != "timed_out" && stageStatus != "error" && stageStatus != "dependency-gated") {
			return nil, false
		}
		seenStages[name] = true
		stageNames = append(stageNames, name)
		if status == "passed" {
			returnCode, returnCodeOK := nonnegativeJSONInteger(stage["return_code"])
			if stageStatus != "passed" || !returnCodeOK || returnCode != 0 {
				return nil, false
			}
		} else if value, present := stage["return_code"]; present && value != nil {
			if _, valid := signedJSONInteger(value); !valid {
				return nil, false
			}
		}
	}
	if status == "passed" && (!buildPassed || !isolated || len(stages) != 2 || !seenStages["configure"] || !seenStages["build"] || stageNames[0] != "configure" || stageNames[1] != "build") {
		return nil, false
	}
	if status != "passed" && buildPassed {
		return nil, false
	}
	projectRoot := filepath.Dir(filepath.Dir(artifact))
	for _, rawArtifact := range artifacts {
		record, ok := rawArtifact.(map[string]any)
		if !ok {
			return nil, false
		}
		path, ok := record["path"].(string)
		expected, hashOK := record["sha256"].(string)
		if !ok || !hashOK || len(expected) != 64 {
			return nil, false
		}
		trusted, valid := trustedProjectArtifact(root, projectRoot, path)
		if !valid {
			return nil, false
		}
		actual, readErr := fileSHA256(filepath.Join(root, filepath.FromSlash(trusted)))
		if readErr != nil {
			return nil, false
		}
		if !strings.EqualFold(expected, actual) {
			return nil, false
		}
	}
	return map[string]any{
		"status":         status,
		"isolated":       isolated,
		"isolation":      payload["isolation"],
		"stage_count":    len(stages),
		"duration_ms":    numberValue(payload["duration_ms"]),
		"artifact_count": artifactCount,
		"error":          payload["error"],
		"artifact":       relativeTo(root, artifact),
	}, true
}

func signedJSONInteger(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(typed.String(), 10, 64)
		return parsed, err == nil
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		if typed < math.MinInt64 || typed > math.MaxInt64 || math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func loadBuildReadiness(root string) (map[string]any, bool) {
	var payload map[string]any
	artifact := ""
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "build-readiness.json" {
			return nil
		}
		if readFileJSON(path, &payload) == nil {
			artifact = path
			return filepath.SkipAll
		}
		return nil
	})
	if payload == nil {
		return nil, false
	}
	return map[string]any{
		"structure_complete":  payload["structure_complete"] == true,
		"dependencies_locked": payload["dependencies_locked"] == true,
		"blocking_reasons":    payload["blocking_reasons"],
		"target_count":        numberValue(payload["target_count"]),
		"dependency_count":    numberValue(payload["dependency_count"]),
		"artifact":            relativeTo(root, artifact),
	}, true
}

func loadModelReconstruction(root string) (map[string]any, bool) {
	var payload map[string]any
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "model-reconstruction.json" {
			return nil
		}
		if readFileJSON(path, &payload) == nil {
			return filepath.SkipAll
		}
		return nil
	})
	if payload == nil {
		return nil, false
	}
	usage, _ := payload["usage"].(map[string]any)
	calls, _ := payload["calls"].([]any)
	return map[string]any{
		"status":               payload["status"],
		"provider":             payload["provider"],
		"model":                payload["model"],
		"call_count":           len(calls),
		"input_tokens":         numberValue(usage["input_tokens"]),
		"output_tokens":        numberValue(usage["output_tokens"]),
		"total_tokens":         numberValue(usage["total_tokens"]),
		"applied_change_count": numberValue(payload["applied_change_count"]),
		"artifact":             relativeTo(root, findModelArtifact(root)),
		"error":                payload["error"],
	}, true
}

func findModelArtifact(root string) string {
	found := ""
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == "model-reconstruction.json" {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func numberValue(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		result, _ := typed.Float64()
		return result
	default:
		result, _ := strconv.ParseFloat(fmt.Sprint(value), 64)
		return result
	}
}

func (s *Server) artifactSummary(root string) map[string]any {
	var files, totalBytes, packageBytes, sourceBytes, logBytes int64
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.Contains(filepath.ToSlash(path), "/.build/") {
			return nil
		}
		files++
		totalBytes += info.Size()
		normalized := filepath.ToSlash(path)
		if filepath.Base(path) == "worker-output.json" {
			logBytes += info.Size()
		}
		if strings.Contains(normalized, "/package/") {
			packageBytes += info.Size()
		}
		if strings.Contains(normalized, "/src/") || strings.Contains(normalized, "/source/") || strings.Contains(normalized, "/gui/") {
			sourceBytes += info.Size()
		}
		return nil
	})
	return map[string]any{"artifact_file_count": files, "artifact_total_bytes": totalBytes, "package_bytes": packageBytes, "source_bytes": sourceBytes, "log_bytes": logBytes, "listed_artifact_count": min(files, 200), "artifact_list_truncated": files > 200}
}

func reconstructionState(state ReconstructionState) ReconstructionState {
	state.BlockingReasons = nil
	for _, gate := range []struct {
		passed bool
		reason string
	}{
		{state.AnalysisComplete, "analysis_not_complete"},
		{state.SourceGenerated, "source_not_generated"},
		{state.StructureComplete, "structure_not_complete"},
		{state.DependenciesLocked, "dependencies_not_locked"},
		{state.BuildPassed, "build_not_passed"},
		{state.BehaviorPassed, "behavior_validation_not_passed"},
	} {
		if !gate.passed {
			state.BlockingReasons = append(state.BlockingReasons, gate.reason)
		}
	}
	state.CompleteBuildable = len(state.BlockingReasons) == 0
	switch {
	case state.CompleteBuildable:
		state.Stage = "complete_buildable"
	case state.BuildPassed:
		state.Stage = "behavior_validation_pending"
	case state.SourceGenerated:
		state.Stage = "build_pending"
	case state.AnalysisComplete:
		state.Stage = "source_generation_pending"
	default:
		state.Stage = "analysis_pending"
	}
	state.UpdatedAt = now()
	return state
}

func (s *Server) deriveLegacyReconstruction(experiment Experiment) ReconstructionState {
	root := filepath.Join(s.cfg.Workspace, "experiments", experiment.ID, "analysis")
	state := ReconstructionState{
		AnalysisComplete: experiment.Status == "completed",
		SourceGenerated:  sourceProjectExists(root),
	}
	if events, err := s.events(experiment.ID); err == nil {
		for _, event := range events {
			if event.Type == "build_completed" {
				state.BuildPassed = true
				state.Iteration++
			}
		}
	}
	return reconstructionState(state)
}

func sourceProjectExists(root string) bool {
	found := false
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.EqualFold(info.Name(), "CMakeLists.txt") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func analysisArgs(x Experiment, out string) []string {
	reconstruct, _ := x.Options["reconstruct"].(bool)
	if reconstruct && strings.EqualFold(filepath.Ext(x.Sample), ".zip") {
		return []string{"-m", "reverse_analyzer.archive_reconstruct", x.Sample, "--out", out}
	}
	args := []string{"-m", "reverse_analyzer", "analyze", x.Sample, "--out", out}
	if reconstruct {
		args = append(args, "--reconstruct")
	}
	for option, flag := range map[string]string{
		"decompile": "--decompile", "gui": "--gui", "gui_visual": "--gui-visual", "reconstruct_gui": "--reconstruct-gui",
	} {
		if enabled, _ := x.Options[option].(bool); enabled {
			args = append(args, flag)
		}
	}
	return args
}

func withoutRawOutput(events []Event) []Event {
	filtered := make([]Event, 0, len(events))
	for _, event := range events {
		if event.Type != "output" {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func byteSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
}

func (s *Server) workerCommand(ctx context.Context, pythonArgs, envNames []string) *exec.Cmd {
	return s.workerCommandWithNetwork(ctx, pythonArgs, envNames, "none")
}

func (s *Server) workerCommandWithNetwork(ctx context.Context, pythonArgs, envNames []string, network string) *exec.Cmd {
	if network != "bridge" {
		network = "none"
	}
	if s.cfg.SandboxRuntime == "docker" || s.cfg.SandboxRuntime == "podman" {
		workspaceMount := fmt.Sprintf("type=bind,src=%s,dst=/workspace", s.cfg.Workspace)
		if s.cfg.SandboxWorkspaceVolume != "" {
			workspaceMount = fmt.Sprintf("type=volume,src=%s,dst=/workspace", s.cfg.SandboxWorkspaceVolume)
		}
		argv := []string{"run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--cpus", "1", "--memory", "1024m", "--network", network, "--mount", workspaceMount, "--workdir", "/workspace", "--entrypoint", "python", s.cfg.SandboxImage}
		for _, name := range envNames {
			argv = append(argv[:len(argv)-1], append([]string{"--env", name}, argv[len(argv)-1:]...)...)
		}
		argv = append(argv, pythonArgs...)
		return exec.CommandContext(ctx, s.cfg.SandboxRuntime, argv...)
	}
	return exec.CommandContext(ctx, s.cfg.Python, pythonArgs...)
}
func (s *Server) cancel(id string) (Experiment, error) {
	return s.cancelAudited(id, nil, nil)
}
func (s *Server) cancelAudited(id string, r *http.Request, who *identity) (Experiment, error) {
	var x Experiment
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return x, err
		}
		defer tx.Rollback()
		if r != nil {
			if err = s.setAuditTransactionContext(tx, r, who, "experiment.cancel"); err != nil {
				return x, err
			}
		}
		var payload []byte
		if err = tx.QueryRow(`SELECT payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&payload); err != nil {
			return x, err
		}
		if err = json.Unmarshal(payload, &x); err != nil {
			return x, err
		}
		if x.Status != "queued" && x.Status != "planned" && x.Status != "running" {
			return x, errors.New("job cannot be cancelled")
		}
		x = s.status(x, "cancelled", "cancelled by user")
		payload, err = json.Marshal(x)
		if err != nil {
			return x, err
		}
		result, err := tx.Exec(`UPDATE experiments SET status='cancelled',updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4 AND status IN ('queued','planned','running')`, x.UpdatedAt, string(payload), id, s.cfg.Workspace)
		if err != nil {
			return x, err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return x, errors.New("job cancellation was already claimed")
		}
		if _, err = insertEventTx(tx, id, "cancelled", "cancelled", "任务已取消", nil); err != nil {
			return x, err
		}
		if err = tx.Commit(); err != nil {
			return x, err
		}
	} else {
		s.mu.Lock()
		if err := readFileJSON(s.experimentPath(id), &x); err != nil {
			s.mu.Unlock()
			return x, err
		}
		if x.Status != "queued" && x.Status != "planned" && x.Status != "running" {
			s.mu.Unlock()
			return x, errors.New("job cannot be cancelled")
		}
		x = s.status(x, "cancelled", "cancelled by user")
		if err := writeFileJSON(s.experimentPath(id), x); err != nil {
			s.mu.Unlock()
			return x, err
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	if stop, ok := s.running[id]; ok {
		stop()
		delete(s.running, id)
	}
	s.mu.Unlock()
	if s.db == nil {
		s.appendEvent(id, "cancelled", "cancelled", "任务已取消", nil)
	}
	return x, nil
}
func (s *Server) retry(id string) (Experiment, error) {
	return s.retryAudited(id, nil, nil)
}
func (s *Server) retryAudited(id string, r *http.Request, who *identity) (Experiment, error) {
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return Experiment{}, err
		}
		defer tx.Rollback()
		if r != nil {
			if err = s.setAuditTransactionContext(tx, r, who, "experiment.retry"); err != nil {
				return Experiment{}, err
			}
		}
		var payload []byte
		var old Experiment
		if err = tx.QueryRow(`SELECT payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&payload); err != nil {
			return Experiment{}, err
		}
		if err = json.Unmarshal(payload, &old); err != nil {
			return Experiment{}, err
		}
		n, err := prepareRetry(old)
		if err != nil {
			return Experiment{}, err
		}
		old.Metadata["retry_successor_id"] = n.ID
		old.UpdatedAt = now()
		oldPayload, _ := json.Marshal(old)
		newPayload, _ := json.Marshal(n)
		if _, err = tx.Exec(`UPDATE experiments SET updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4`, old.UpdatedAt, string(oldPayload), id, s.cfg.Workspace); err != nil {
			return Experiment{}, err
		}
		if _, err = tx.Exec(`INSERT INTO experiments(id,workspace_id,status,created_at,updated_at,payload) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, n.ID, s.cfg.Workspace, n.Status, n.CreatedAt, n.UpdatedAt, string(newPayload)); err != nil {
			return Experiment{}, err
		}
		if _, err = insertEventTx(tx, n.ID, "queued", "queued", "重试任务已进入队列", map[string]any{"retry_of": id}); err != nil {
			return Experiment{}, err
		}
		if err = tx.Commit(); err != nil {
			return Experiment{}, err
		}
		return n, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var old Experiment
	if err := readFileJSON(s.experimentPath(id), &old); err != nil {
		return Experiment{}, err
	}
	n, err := prepareRetry(old)
	if err != nil {
		return Experiment{}, err
	}
	old.Metadata["retry_successor_id"] = n.ID
	old.UpdatedAt = now()
	if err = writeFileJSON(s.experimentPath(n.ID), n); err != nil {
		return Experiment{}, err
	}
	if err = writeFileJSON(s.experimentPath(id), old); err != nil {
		return Experiment{}, err
	}
	return n, nil
}

func prepareRetry(old Experiment) (Experiment, error) {
	completedRepairRetry := old.Status == "completed" && repairRetryRequired(old.Metadata)
	if old.Status != "failed" && old.Status != "cancelled" && !completedRepairRetry {
		return Experiment{}, errors.New("only failed or cancelled jobs can retry")
	}
	if old.Metadata != nil && strings.TrimSpace(fmt.Sprint(old.Metadata["retry_successor_id"])) != "" && fmt.Sprint(old.Metadata["retry_successor_id"]) != "<nil>" {
		return Experiment{}, errors.New("job retry was already claimed")
	}
	n := old
	n.ID = newID()
	n.Status = "queued"
	n.CreatedAt = now()
	n.UpdatedAt = n.CreatedAt
	n.History = []map[string]any{{"timestamp": n.CreatedAt, "status": "queued", "detail": "retry created"}}
	n.Artifacts = []map[string]any{}
	n.Summary = nil
	n.Error = ""
	if n.Metadata == nil {
		n.Metadata = map[string]any{}
	}
	for _, key := range []string{"automated_build", "behavior_validation", "build_repair_loop", "behavior_repair_loop", "model_reconstruction", "execution_confirmation", "project_readiness"} {
		delete(n.Metadata, key)
	}
	n.Metadata["retry_of"] = old.ID
	n.Reconstruction = reconstructionState(ReconstructionState{})
	return n, nil
}

func repairRetryRequired(metadata map[string]any) bool {
	for _, key := range []string{"build_repair_loop", "behavior_repair_loop"} {
		state, _ := metadata[key].(map[string]any)
		status := fmt.Sprint(state["status"])
		if status == "failed" || status == "dependency-gated" || status == "exhausted" {
			return true
		}
	}
	return false
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		method(w)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		s.uploadMultipart(w, r)
		return
	}
	var p struct {
		Filename string `json:"filename"`
		Content  string `json:"content_base64"`
	}
	if readJSON(r, &p) != nil {
		bad(w, "invalid upload")
		return
	}
	name := filepath.Base(p.Filename)
	data, err := base64.StdEncoding.DecodeString(p.Content)
	if err != nil || len(data) > 16<<20 {
		bad(w, "invalid or oversized upload")
		return
	}
	dir := filepath.Join(s.cfg.Workspace, "uploads")
	_ = os.MkdirAll(dir, 0755)
	dest := filepath.Join(dir, newID()+"-"+name)
	if err = os.WriteFile(dest, data, 0600); err != nil {
		respond(w, nil, err)
		return
	}
	rel, _ := filepath.Rel(s.cfg.Workspace, dest)
	writeJSON(w, 201, map[string]any{"path": filepath.ToSlash(rel), "size": len(data), "executed": false})
}

func (s *Server) uploadMultipart(w http.ResponseWriter, r *http.Request) {
	const maxUpload = int64(512 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+1<<20)
	reader, err := r.MultipartReader()
	if err != nil {
		bad(w, "上传请求必须包含文件")
		return
	}
	for {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			bad(w, "无法读取上传内容")
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			part.Close()
			continue
		}
		name := filepath.Base(part.FileName())
		dir := filepath.Join(s.cfg.Workspace, "uploads")
		if err = os.MkdirAll(dir, 0755); err != nil {
			respond(w, nil, err)
			return
		}
		dest := filepath.Join(dir, newID()+"-"+name)
		temporary := dest + ".uploading"
		file, createErr := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			respond(w, nil, createErr)
			return
		}
		size, copyErr := io.Copy(file, io.LimitReader(part, maxUpload+1))
		closeErr := file.Close()
		part.Close()
		if copyErr != nil || closeErr != nil || size > maxUpload {
			_ = os.Remove(temporary)
			if size > maxUpload {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "样本超过 512MB 上传上限"})
				return
			}
			respond(w, nil, errors.Join(copyErr, closeErr))
			return
		}
		if err = os.Rename(temporary, dest); err != nil {
			_ = os.Remove(temporary)
			respond(w, nil, err)
			return
		}
		rel, _ := filepath.Rel(s.cfg.Workspace, dest)
		writeJSON(w, http.StatusCreated, map[string]any{"path": filepath.ToSlash(rel), "filename": name, "size": size, "executed": false})
		return
	}
	bad(w, "请选择需要上传的本地样本")
}
func (s *Server) artifact(w http.ResponseWriter, r *http.Request) {
	p, err := s.safePath(r.URL.Query().Get("path"))
	if err != nil {
		bad(w, err.Error())
		return
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "产物不存在"})
		return
	}
	workspace, workspaceErr := filepath.EvalSymlinks(s.cfg.Workspace)
	if workspaceErr != nil {
		respond(w, nil, workspaceErr)
		return
	}
	rel, relErr := filepath.Rel(workspace, resolved)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		bad(w, "产物路径必须位于工作区内")
		return
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 3 || parts[0] != "experiments" || len(parts[1]) != 32 {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "artifact must belong to an experiment in the current workspace"})
		return
	}
	if _, err = s.loadExperiment(parts[1]); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "artifact experiment is not available in the current workspace"})
		return
	}
	if r.URL.Query().Get("preview") == "1" {
		if !strings.EqualFold(filepath.Ext(resolved), ".json") {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "仅支持预览 JSON 产物"})
			return
		}
		var payload any
		if err = readBoundedJSON(resolved, maxArtifactPreviewBytes, &payload); err != nil {
			if info, statErr := os.Stat(resolved); statErr == nil && info.Size() > maxArtifactPreviewBytes {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "产物超过 256KB 预览上限", "download": true})
				return
			}
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "JSON 产物损坏，无法预览"})
			return
		}
		info, _ := os.Stat(resolved)
		writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(rel), "size": info.Size(), "preview": payload})
		return
	}
	http.ServeFile(w, r, resolved)
}

func (s *Server) knowledge(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "knowledge", "documents.json")
	switch r.Method {
	case "GET":
		writeJSON(w, 200, map[string]any{"documents": s.readKnowledge()})
	case "POST":
		var p map[string]any
		if readJSON(r, &p) != nil {
			bad(w, "invalid JSON")
			return
		}
		p["id"] = newID()
		p["updated_at"] = now()
		if s.dbErr != nil {
			respond(w, nil, s.dbErr)
			return
		}
		if s.db != nil {
			payload, err := json.Marshal(p)
			if err == nil {
				_, err = s.db.Exec(`INSERT INTO knowledge_documents(id,workspace_id,updated_at,payload) VALUES($1,$2,$3,$4::jsonb)`, p["id"], s.cfg.Workspace, p["updated_at"], string(payload))
			}
			if err != nil {
				respond(w, nil, err)
				return
			}
			writeJSON(w, 201, p)
			return
		}
		docs := s.readKnowledge()
		docs = append(docs, p)
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		err := writeFileJSON(path, docs)
		if err != nil {
			respond(w, nil, err)
			return
		}
		writeJSON(w, 201, p)
	default:
		method(w)
	}
}

func (s *Server) knowledgeItem(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/knowledge/"), "/")
	if len(id) != 32 || strings.Contains(id, "/") {
		bad(w, "invalid knowledge document id")
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		method(w)
		return
	}
	if s.dbErr != nil {
		respond(w, nil, s.dbErr)
		return
	}
	if s.db != nil {
		if r.Method == http.MethodDelete {
			result, err := s.db.Exec(`DELETE FROM knowledge_documents WHERE id=$1 AND workspace_id=$2`, id, s.cfg.Workspace)
			s.respondKnowledgeMutation(w, result, nil, err)
			return
		}
		var patch map[string]any
		if readJSON(r, &patch) != nil {
			bad(w, "invalid JSON")
			return
		}
		var payload []byte
		err := s.db.QueryRow(`SELECT payload FROM knowledge_documents WHERE id=$1 AND workspace_id=$2`, id, s.cfg.Workspace).Scan(&payload)
		if err != nil {
			s.respondKnowledgeMutation(w, nil, nil, err)
			return
		}
		var doc map[string]any
		if err = json.Unmarshal(payload, &doc); err == nil {
			mergeKnowledge(doc, patch)
			payload, err = json.Marshal(doc)
		}
		if err == nil {
			_, err = s.db.Exec(`UPDATE knowledge_documents SET updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4`, doc["updated_at"], string(payload), id, s.cfg.Workspace)
		}
		if err != nil {
			respond(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, doc)
		return
	}

	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "knowledge", "documents.json")
	docs := s.readKnowledge()
	index := -1
	for i, doc := range docs {
		if fmt.Sprint(doc["id"]) == id {
			index = i
			break
		}
	}
	if index < 0 {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		docs = append(docs[:index], docs[index+1:]...)
		if err := writeFileJSON(path, docs); err != nil {
			respond(w, nil, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var patch map[string]any
	if readJSON(r, &patch) != nil {
		bad(w, "invalid JSON")
		return
	}
	mergeKnowledge(docs[index], patch)
	if err := writeFileJSON(path, docs); err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, docs[index])
}

func mergeKnowledge(doc, patch map[string]any) {
	for _, key := range []string{"title", "content", "type", "tags"} {
		if value, ok := patch[key]; ok {
			doc[key] = value
		}
	}
	doc["updated_at"] = now()
}

func (s *Server) respondKnowledgeMutation(w http.ResponseWriter, result sql.Result, payload any, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "knowledge document not found"})
		return
	}
	if err != nil {
		respond(w, nil, err)
		return
	}
	if result != nil {
		rows, _ := result.RowsAffected()
		if rows == 0 {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "knowledge document not found"})
			return
		}
	}
	if payload == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}
func (s *Server) readKnowledge() []map[string]any {
	if s.db != nil && s.dbErr == nil {
		rows, err := s.db.Query(`SELECT payload FROM knowledge_documents WHERE workspace_id=$1 ORDER BY updated_at DESC LIMIT 100`, s.cfg.Workspace)
		if err != nil {
			return []map[string]any{}
		}
		defer rows.Close()
		docs := []map[string]any{}
		for rows.Next() {
			var payload []byte
			var doc map[string]any
			if rows.Scan(&payload) == nil && json.Unmarshal(payload, &doc) == nil {
				docs = append(docs, doc)
			}
		}
		return docs
	}
	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "knowledge", "documents.json")
	var docs []map[string]any
	if readFileJSON(path, &docs) != nil {
		return []map[string]any{}
	}
	return docs
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"fallback": "rule_based", "providers": s.providerProfiles()})
	case http.MethodPut, http.MethodPost:
		var profile providerProfile
		if readJSON(r, &profile) != nil {
			bad(w, "invalid provider profile")
			return
		}
		if err := s.saveProvider(profile); err != nil {
			bad(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, profile)
	default:
		method(w)
	}
}
func (s *Server) providerTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		method(w)
		return
	}
	var payload struct {
		Name    string           `json:"name"`
		Profile *providerProfile `json:"profile,omitempty"`
	}
	if readJSON(r, &payload) != nil || payload.Name == "" {
		bad(w, "provider name is required")
		return
	}
	profiles := s.providerProfiles()
	if payload.Profile != nil {
		if payload.Profile.Name != payload.Name {
			bad(w, "provider test profile identity mismatch")
			return
		}
		preferredProviderModel(payload.Profile)
		if err := validateProvider(*payload.Profile); err != nil {
			bad(w, err.Error())
			return
		}
		profiles = []providerProfile{*payload.Profile}
	}
	for _, profile := range profiles {
		if profile.Name == payload.Name {
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			defer cancel()
			result, err := s.testProvider(ctx, profile)
			if err != nil {
				s.recordProvider(profile.Name, true)
				writeJSON(w, http.StatusBadGateway, map[string]any{"name": profile.Name, "status": "failed", "error": err.Error(), "network_call": true})
				return
			}
			writeJSON(w, http.StatusOK, result)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "provider not found"})
}
func (s *Server) environment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.environmentPayload())
}
func (s *Server) environmentPayload() map[string]any {
	payload := map[string]any{"generated_at": now(), "summary": map[string]int{}, "workflows": []any{}, "acceptance_fixtures": []any{}}
	if report, err := s.pythonJSON(20*time.Second, "environment", "validate", "--json"); err == nil {
		payload = report
		if workflows, ok := payload["workflows"].(map[string]any); ok {
			items := make([]map[string]any, 0, len(workflows))
			for id, raw := range workflows {
				item, _ := raw.(map[string]any)
				if item == nil {
					item = map[string]any{}
				}
				if _, exists := item["id"]; !exists {
					item["id"] = id
				}
				if missing, exists := item["missing"]; !exists || missing == nil {
					item["missing"] = append(stringSlice(item["required"]), stringSlice(item["any_of"])...)
				}
				items = append(items, item)
			}
			sort.Slice(items, func(i, j int) bool { return fmt.Sprint(items[i]["id"]) < fmt.Sprint(items[j]["id"]) })
			payload["workflows"] = items
		}
	} else {
		payload["engine_error"] = err.Error()
	}
	payload["sandbox"] = map[string]any{"status": runtimeStatus(), "configured_runtime": s.cfg.SandboxRuntime}
	payload["storage"] = map[string]any{"backend": storageBackend()}
	payload["providers"] = []any{}
	return payload
}

func stringSlice(raw any) []string {
	items := []string{}
	if values, ok := raw.([]any); ok {
		for _, value := range values {
			if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
				items = append(items, text)
			}
		}
	}
	return items
}
func runtimeStatus() string {
	if _, e := exec.LookPath("docker"); e == nil {
		return "available"
	}
	if _, e := exec.LookPath("podman"); e == nil {
		return "available"
	}
	return "dependency-gated"
}
func storageBackend() string {
	if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") != "" {
		return "postgresql"
	}
	return "json"
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	if payload, err := s.pythonJSON(20*time.Second, "platform", "catalog"); err == nil {
		writeJSON(w, 200, payload)
		return
	}
	skills := files(filepath.Join(s.cfg.Workspace, "reverse-skills"), "SKILL.md")
	scripts := extensions(filepath.Join(s.cfg.Workspace, "scripts"), map[string]bool{".py": true, ".ps1": true, ".sh": true, ".cmd": true, ".bat": true})
	deps := []map[string]any{}
	var manifest map[string]any
	_ = readFileJSON(filepath.Join(s.cfg.Workspace, "config", "github-tools.lock.json"), &manifest)
	if raw, ok := manifest["tools"].([]any); ok {
		for _, x := range raw {
			if m, ok := x.(map[string]any); ok {
				m["execution_boundary"] = "manifest_only"
				deps = append(deps, m)
			}
		}
	}
	skillItems := make([]map[string]any, 0, len(skills))
	for _, p := range skills {
		skillItems = append(skillItems, map[string]any{"id": p, "name": filepath.Base(filepath.Dir(p)), "path": p, "execution_boundary": "instruction_asset"})
	}
	scriptItems := make([]map[string]any, 0, len(scripts))
	for _, p := range scripts {
		scriptItems = append(scriptItems, map[string]any{"id": p, "name": filepath.Base(p), "path": p, "execution_boundary": "file_inventory_only"})
	}
	total := len(skillItems) + len(scriptItems) + len(deps)
	writeJSON(w, 200, map[string]any{"generated_at": now(), "summary": map[string]int{"skill_total": len(skillItems), "script_total": len(scriptItems), "github_tool_total": len(deps)}, "integration": map[string]any{"discovered_total": total, "cataloged_total": total, "catalog_coverage_percent": 100}, "skills": skillItems, "tools": []any{}, "providers": []any{}, "scripts": scriptItems, "github_tools": deps})
}

func (s *Server) pythonJSON(timeout time.Duration, args ...string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.Python, append([]string{"-m", "reverse_analyzer"}, args...)...)
	cmd.Dir = s.cfg.Workspace
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(s.cfg.Frontend, filepath.Clean("/"+r.URL.Path))
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		if t := mime.TypeByExtension(filepath.Ext(p)); t != "" {
			w.Header().Set("Content-Type", t)
		}
		http.ServeFile(w, r, p)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.Frontend, "index.html"))
}
func (s *Server) safePath(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("path is required")
	}
	p := raw
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.cfg.Workspace, p)
	}
	p, _ = filepath.Abs(p)
	rel, err := filepath.Rel(s.cfg.Workspace, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("path must stay inside workspace")
	}
	return p, nil
}
func (s *Server) experimentPath(id string) string {
	return filepath.Join(s.cfg.Workspace, "experiments", id+".json")
}
func (s *Server) eventPath(id string) string {
	return filepath.Join(s.cfg.Workspace, "experiments", id, "events.jsonl")
}
func (s *Server) saveExperiment(x Experiment) error {
	if s.dbErr != nil {
		return s.dbErr
	}
	if s.db != nil {
		payload, err := json.Marshal(x)
		if err != nil {
			return err
		}
		result, err := s.db.Exec(`INSERT INTO experiments(id,workspace_id,status,created_at,updated_at,payload) VALUES($1,$2,$3,$4,$5,$6::jsonb)
			ON CONFLICT(id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at,payload=excluded.payload WHERE experiments.workspace_id=excluded.workspace_id`, x.ID, s.cfg.Workspace, x.Status, x.CreatedAt, x.UpdatedAt, string(payload))
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return errors.New("experiment id belongs to another workspace")
		}
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.MkdirAll(filepath.Join(s.cfg.Workspace, "experiments"), 0755)
	return writeFileJSON(s.experimentPath(x.ID), x)
}
func (s *Server) loadExperiment(id string) (Experiment, error) {
	if len(id) != 32 {
		return Experiment{}, errors.New("invalid experiment id")
	}
	var x Experiment
	if s.dbErr != nil {
		return x, s.dbErr
	}
	if s.db != nil {
		var payload []byte
		err := s.db.QueryRow(`SELECT payload FROM experiments WHERE id=$1 AND workspace_id=$2`, id, s.cfg.Workspace).Scan(&payload)
		if err != nil {
			return x, err
		}
		err = json.Unmarshal(payload, &x)
		return x, err
	}
	err := readFileJSON(s.experimentPath(id), &x)
	return x, err
}
func (s *Server) listExperiments() ([]Experiment, error) {
	if s.dbErr != nil {
		return nil, s.dbErr
	}
	if s.db != nil {
		rows, err := s.db.Query(`SELECT payload FROM experiments WHERE workspace_id=$1 ORDER BY updated_at DESC LIMIT 100`, s.cfg.Workspace)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []Experiment{}
		for rows.Next() {
			var payload []byte
			var x Experiment
			if err = rows.Scan(&payload); err != nil {
				return nil, err
			}
			if err = json.Unmarshal(payload, &x); err != nil {
				return nil, err
			}
			x.Name = filepath.Base(x.Sample)
			items = append(items, x)
		}
		return items, rows.Err()
	}
	paths, _ := filepath.Glob(filepath.Join(s.cfg.Workspace, "experiments", "*.json"))
	items := []Experiment{}
	for _, p := range paths {
		var x Experiment
		if readFileJSON(p, &x) == nil {
			x.Name = filepath.Base(x.Sample)
			items = append(items, x)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt > items[j].UpdatedAt })
	return items, nil
}
func (s *Server) status(x Experiment, status string, detail any) Experiment {
	x.Status = status
	x.UpdatedAt = now()
	x.History = append(x.History, map[string]any{"timestamp": x.UpdatedAt, "status": status, "detail": detail})
	return x
}
func (s *Server) appendEvent(id, kind, status, message string, data map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil && s.dbErr == nil {
		tx, err := s.db.Begin()
		if err != nil {
			log.Printf("append event failed for experiment %s", id)
			return
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`SELECT 1 FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace); err != nil {
			log.Printf("append event rejected for experiment %s", id)
			return
		}
		sequence, err := insertEventTx(tx, id, kind, status, message, data)
		if err != nil {
			log.Printf("append event insert failed for experiment %s", id)
			return
		}
		if err = tx.Commit(); err != nil {
			log.Printf("append event commit failed for experiment %s", id)
			return
		}
		s.eventSeq[id] = sequence
		return
	}
	sequence := s.eventSeq[id]
	if sequence == 0 {
		existing, _ := s.eventsUnlocked(id)
		if len(existing) > 0 {
			sequence = existing[len(existing)-1].Sequence
		}
	}
	sequence++
	s.eventSeq[id] = sequence
	event := Event{sequence, now(), kind, status, message, data}
	path := s.eventPath(id)
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		b, _ := json.Marshal(event)
		_, _ = f.Write(append(b, '\n'))
	}
}

func insertEventTx(tx *sql.Tx, id, kind, status, message string, data map[string]any) (int64, error) {
	var sequence int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(sequence),0)+1 FROM flow_events WHERE experiment_id=$1`, id).Scan(&sequence); err != nil {
		return 0, err
	}
	event := Event{sequence, now(), kind, status, message, data}
	payload, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`INSERT INTO flow_events(experiment_id,sequence,payload) VALUES($1,$2,$3::jsonb)`, id, sequence, string(payload)); err != nil {
		return 0, err
	}
	return sequence, nil
}
func (s *Server) events(id string) ([]Event, error) {
	if s.dbErr != nil {
		return nil, s.dbErr
	}
	if s.db != nil {
		rows, err := s.db.Query(`SELECT payload FROM flow_events WHERE experiment_id=$1 ORDER BY sequence`, id)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []Event{}
		for rows.Next() {
			var payload []byte
			var e Event
			if err = rows.Scan(&payload); err != nil {
				return nil, err
			}
			if err = json.Unmarshal(payload, &e); err != nil {
				return nil, err
			}
			out = append(out, e)
		}
		return out, rows.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eventsUnlocked(id)
}
func (s *Server) eventsUnlocked(id string) ([]Event, error) {
	b, err := os.ReadFile(s.eventPath(id))
	if os.IsNotExist(err) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Event{}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
func (s *Server) collectArtifacts(root string) []map[string]any {
	out := []map[string]any{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == "CMakeFiles" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		normalized := filepath.ToSlash(p)
		if strings.Contains(normalized, "/.build/") && map[string]bool{"CMakeCache.txt": true, "Makefile": true, "cmake_install.cmake": true}[info.Name()] {
			return nil
		}
		if len(out) < 200 {
			rel, _ := filepath.Rel(s.cfg.Workspace, p)
			out = append(out, map[string]any{"path": filepath.ToSlash(rel), "name": info.Name(), "size": info.Size()})
		}
		return nil
	})
	return out
}

func files(root, name string) []string {
	out := []string{}
	_ = filepath.Walk(root, func(p string, i os.FileInfo, e error) error {
		if e == nil && !i.IsDir() && i.Name() == name {
			out = append(out, filepath.ToSlash(p))
		}
		return nil
	})
	return out
}
func extensions(root string, ext map[string]bool) []string {
	out := []string{}
	_ = filepath.Walk(root, func(p string, i os.FileInfo, e error) error {
		if e == nil && !i.IsDir() && ext[strings.ToLower(filepath.Ext(p))] {
			out = append(out, filepath.ToSlash(p))
		}
		return nil
	})
	return out
}
func newID() string { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func now() string   { return time.Now().UTC().Format(time.RFC3339Nano) }
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v)
}
func readFileJSON(p string, v any) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func writeFileJSON(p string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	tmp := p + ".tmp"
	if e = os.WriteFile(tmp, append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(tmp, p)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func respond(w http.ResponseWriter, v any, e error) {
	if e != nil {
		status := http.StatusInternalServerError
		var databaseError *pq.Error
		if errors.As(e, &databaseError) && databaseError.Code == "55000" {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{"error": e.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func bad(w http.ResponseWriter, m string) { writeJSON(w, 400, map[string]any{"error": m}) }
func method(w http.ResponseWriter)        { writeJSON(w, 405, map[string]any{"error": "method not allowed"}) }
