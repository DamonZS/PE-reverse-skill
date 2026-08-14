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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
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
const terminalMaxLines = 2000
const terminalMaxBytes = 2 << 20
const terminalEventLines = 200
const terminalSessionTTL = 30 * time.Minute

type Config struct {
	Workspace, Frontend, Addr, Token, Python string
	SandboxRuntime, SandboxImage             string
	SandboxWorkspaceVolume                   string
	RunnerURL, RunnerToken                   string
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
	Orchestration  *OrchestrationState `json:"orchestration,omitempty"`
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
type OrchestrationState struct {
	Version           int                     `json:"version"`
	LastEventSequence int64                   `json:"last_event_sequence"`
	Flow              OrchestrationFlow       `json:"flow"`
	Tasks             []OrchestrationTask     `json:"tasks"`
	Subtasks          []OrchestrationSubtask  `json:"subtasks"`
	ToolCalls         []OrchestrationToolCall `json:"tool_calls"`
	UpdatedAt         string                  `json:"updated_at"`
}
type OrchestrationFlow struct {
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}
type OrchestrationTask struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Input  string `json:"input,omitempty"`
	Result string `json:"result,omitempty"`
}
type OrchestrationSubtask struct {
	ID          string `json:"id"`
	TaskID      string `json:"task_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Result      string `json:"result,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}
type OrchestrationToolCall struct {
	ID        string         `json:"id"`
	RootID    string         `json:"root_id,omitempty"`
	Attempt   int            `json:"attempt,omitempty"`
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	Result    string         `json:"result,omitempty"`
	Timestamp string         `json:"timestamp,omitempty"`
	StartedAt string         `json:"started_at,omitempty"`
	EndedAt   string         `json:"ended_at,omitempty"`
	Duration  string         `json:"duration,omitempty"`
	RetryOf   string         `json:"retry_of,omitempty"`
	Canceled  bool           `json:"canceled,omitempty"`
	Args      map[string]any `json:"args,omitempty"`
}

type toolCallExecutor func(context.Context, Experiment, OrchestrationToolCall) (string, error)
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
type runnerJobRequest struct {
	Kind    string            `json:"kind"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Network string            `json:"network,omitempty"`
	Project string            `json:"project,omitempty"`
	Command string            `json:"command,omitempty"`
}

type workerExecution struct {
	Output io.ReadCloser
	Wait   func() error
}

type workerLeaseClaim struct {
	ownerID      string
	fencingToken int64
}

type terminalSession struct {
	ID           string
	ExperimentID string
	Command      string
	StartedAt    string
	EndedAt      string
	Status       string
	ExitCode     *int
	Error        string
	Output       []map[string]any
	OutputBytes  int
	DroppedLines int
	Truncated    bool
	Cmd          *exec.Cmd
	Cancel       context.CancelFunc
	Mu           sync.Mutex
}

type Server struct {
	cfg           Config
	mux           *http.ServeMux
	mu            sync.Mutex
	running       map[string]context.CancelFunc
	toolRunning   map[string]context.CancelFunc
	toolExecutors map[string]toolCallExecutor
	workers       sync.WaitGroup
	eventSeq      map[string]int64
	terminals     map[string]*terminalSession
	db            *sql.DB
	dbErr         error
	auditErr      error
	migrationsOK  bool
	workerOwner   string
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
	cfg := Config{Workspace: workspace, Frontend: frontend, Addr: env("REVERSE_ANALYZER_WEB_ADDR", "127.0.0.1:8090"), Token: os.Getenv("REVERSE_ANALYZER_WEB_TOKEN"), Python: env("REVERSE_ANALYZER_PYTHON", "python"), SandboxRuntime: strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_SANDBOX_RUNTIME")), SandboxImage: env("REVERSE_ANALYZER_SANDBOX_IMAGE", "reverse-analyzer:web"), SandboxWorkspaceVolume: strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_SANDBOX_WORKSPACE_VOLUME")), RunnerURL: strings.TrimRight(strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_URL")), "/"), RunnerToken: strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_TOKEN")), Timeout: time.Duration(seconds) * time.Second, Production: strings.EqualFold(env("REVERSE_ANALYZER_ENV", "local-dev"), "production"), AllowAnonymous: strings.EqualFold(os.Getenv("REVERSE_ANALYZER_ALLOW_ANONYMOUS"), "true"), AllowedOrigins: csvSet(os.Getenv("REVERSE_ANALYZER_CORS_ALLOWED_ORIGINS")), TrustedProxyCIDRs: csvValues(os.Getenv("REVERSE_ANALYZER_TRUSTED_PROXY_CIDRS"))}
	if cfg.RunnerToken == "" {
		if tokenFile := strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_TOKEN_FILE")); tokenFile != "" {
			content, readErr := os.ReadFile(tokenFile)
			if readErr != nil {
				return Config{}, fmt.Errorf("runner token file: %w", readErr)
			}
			cfg.RunnerToken = strings.TrimSpace(string(content))
		}
	}
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
	if cfg.RunnerURL == "" || cfg.RunnerToken == "" {
		return errors.New("production requires an authenticated isolated runner")
	}
	if cfg.SandboxRuntime != "" {
		return errors.New("production control plane cannot own a local sandbox runtime")
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
	s := &Server{
		cfg: cfg, mux: http.NewServeMux(), running: map[string]context.CancelFunc{},
		toolRunning: map[string]context.CancelFunc{}, toolExecutors: defaultToolCallExecutors(),
		eventSeq: map[string]int64{}, terminals: map[string]*terminalSession{}, workerOwner: newID(),
	}
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
	if origin == "" || sameOriginRequest(r, origin) {
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

func sameOriginRequest(r *http.Request, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	requestHost := strings.TrimSpace(r.Host)
	if requestHost == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, requestScheme(r)) && strings.EqualFold(parsed.Host, requestHost)
}

func requestScheme(r *http.Request) string {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return "https"
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
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
	if s.db != nil {
		rows, err := s.db.Query(`SELECT id FROM experiments WHERE workspace_id=$1 AND status='running' ORDER BY updated_at`, s.cfg.Workspace)
		if err != nil {
			return
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				_ = rows.Close()
				return
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		for _, id := range ids {
			if err = s.recoverInterruptedExperiment(id); err != nil {
				log.Printf("recover interrupted experiment %s failed: %v", id, err)
			}
		}
		return
	}
	items, err := s.listExperiments()
	if err != nil {
		return
	}
	for _, experiment := range items {
		if experiment.Status != "running" {
			continue
		}
		experiment = interruptedExperiment(experiment)
		if s.saveExperiment(experiment) == nil {
			s.appendEvent(experiment.ID, "recovered", "failed", "服务重启后检测到中断任务，已标记失败并允许重试", nil)
		}
	}
}

func interruptedExperiment(experiment Experiment) Experiment {
	experiment.Status = "failed"
	experiment.UpdatedAt = now()
	experiment.Error = "worker interrupted by control-plane restart; retry is available"
	experiment.History = append(experiment.History, map[string]any{"timestamp": experiment.UpdatedAt, "status": "failed", "detail": "control plane restarted while worker was running"})
	if experiment.Orchestration != nil {
		experiment.Orchestration.Flow.Status = "failed"
		experiment.Orchestration.Flow.UpdatedAt = experiment.UpdatedAt
		experiment.Orchestration.Tasks = ensureOrchestrationTasks(experiment.Orchestration.Tasks, experiment)
		experiment.Orchestration.Tasks[0].Status = "failed"
		experiment.Orchestration.Tasks[0].Result = orchestrationResult(experiment)
		experiment.Orchestration.UpdatedAt = experiment.UpdatedAt
	}
	experiment.Reconstruction.BuildPassed = false
	experiment.Reconstruction.BehaviorPassed = false
	experiment.Reconstruction.CompleteBuildable = false
	experiment.Reconstruction.BlockingReasons = append(experiment.Reconstruction.BlockingReasons, "worker interrupted; build and behavior evidence must be regenerated")
	return experiment
}

func (s *Server) recoverInterruptedExperiment(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var payload []byte
	var status string
	if err = tx.QueryRow(`SELECT status,payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&status, &payload); err != nil {
		return err
	}
	if status != "running" {
		return nil
	}
	var active bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2 AND expires_at>now())`, id, s.cfg.Workspace).Scan(&active); err != nil {
		return err
	}
	if active {
		return nil
	}
	var experiment Experiment
	if err = json.Unmarshal(payload, &experiment); err != nil {
		return err
	}
	experiment = interruptedExperiment(experiment)
	if _, err = tx.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2 AND expires_at<=now()`, id, s.cfg.Workspace); err != nil {
		return err
	}
	event, err := insertEventRecordTx(tx, id, "recovered", "failed", "服务重启后检测到中断任务，已标记失败并允许重试", nil)
	if err != nil {
		return err
	}
	experiment = s.ensureOrchestrationState(experiment, []Event{event})
	payload, err = json.Marshal(experiment)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE experiments SET status='failed',updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4 AND status='running'`, experiment.UpdatedAt, string(payload), id, s.cfg.Workspace)
	if err != nil {
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return errors.New("interrupted experiment recovery lost its state claim")
	}
	return tx.Commit()
}

func (s *Server) close() {
	s.mu.Lock()
	for id, cancel := range s.running {
		cancel()
		delete(s.running, id)
	}
	for id, cancel := range s.toolRunning {
		cancel()
		delete(s.toolRunning, id)
	}
	for id, session := range s.terminals {
		session.Mu.Lock()
		if session.Cancel != nil {
			session.Cancel()
		}
		if session.Status == "running" {
			exitCode := -1
			session.Status = "stopped"
			session.ExitCode = &exitCode
			session.EndedAt = now()
		}
		session.Mu.Unlock()
		delete(s.terminals, id)
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
	checks := map[string]string{"audit": "ready", "database": "ready", "workspace": "ready", "runner": "ready"}
	if s.auditError() != nil {
		reasons = append(reasons, "audit persistence degraded")
		checks["audit"] = "not_ready"
	}
	if s.cfg.RunnerURL != "" {
		if s.cfg.RunnerToken == "" {
			reasons = append(reasons, "runner authentication is not configured")
			checks["runner"] = "not_ready"
		} else if err := s.probeRunner(r.Context()); err != nil {
			reasons = append(reasons, "runner unavailable: "+err.Error())
			checks["runner"] = "not_ready"
		}
	} else if s.cfg.Production {
		reasons = append(reasons, "isolated runner is not configured")
		checks["runner"] = "not_ready"
	}
	if s.dbErr != nil {
		checks["database"] = "not_ready"
		reasons = append(reasons, "database unavailable")
	} else if os.Getenv("REVERSE_ANALYZER_DATABASE_URL") != "" {
		if s.db == nil || !s.migrationsOK {
			reasons = append(reasons, "database migrations not ready")
			checks["database"] = "not_ready"
		} else if err := s.db.PingContext(r.Context()); err != nil {
			reasons = append(reasons, "database ping failed")
			checks["database"] = "not_ready"
		}
	}
	probe, err := os.CreateTemp(s.cfg.Workspace, ".ready-*")
	if err != nil {
		reasons = append(reasons, "workspace is not writable")
		checks["workspace"] = "not_ready"
	} else {
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
	}
	if len(reasons) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "checks": checks, "reasons": reasons})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": checks, "storage": storageBackend()})
}

func (s *Server) probeRunner(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.RunnerURL+"/healthz", nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-Runner-Token", s.cfg.RunnerToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned %d", response.StatusCode)
	}
	return nil
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
		workflowType, workflowErr := normalizeWorkflowType(fmt.Sprint(p["workflow_type"]))
		if workflowErr != nil {
			bad(w, workflowErr.Error())
			return
		}
		mode := fmt.Sprint(p["mode"])
		resolved := ""
		if workflowType == "authorized_pentest" {
			if err := validateAuthorizedEndpoint(target, strings.TrimSpace(fmt.Sprint(p["endpoint"]))); err != nil {
				bad(w, err.Error())
				return
			}
		} else if target != "" && target != "<nil>" {
			var err error
			resolved, err = s.safePath(target)
			if err != nil {
				bad(w, err.Error())
				return
			}
			if st, statErr := os.Stat(resolved); statErr != nil || st.IsDir() {
				bad(w, "目标文件不存在：请上传本地样本，或填写容器工作区内的文件路径")
				return
			}
		} else if workflowType == "reverse_analysis" || workflowType == "binary_patch" {
			bad(w, "该作业需要上传本地样本，或填写容器工作区内的文件路径")
			return
		}
		workflowParams, workflowParamsErr := s.workflowParameters(workflowType, p)
		if workflowParamsErr != nil {
			bad(w, workflowParamsErr.Error())
			return
		}
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
		id := newID()
		t := now()
		status := "queued"
		if workflowType == "memory_patch" || workflowType == "process_injection" {
			status = "awaiting_ai_plan"
		}
		nameTarget := filepath.Base(resolved)
		if workflowType == "authorized_pentest" {
			nameTarget = strings.TrimSpace(fmt.Sprint(p["endpoint"]))
		}
		if nameTarget == "" || nameTarget == "." || nameTarget == string(filepath.Separator) {
			nameTarget = "意图任务"
		}
		x := Experiment{
			Schema: 1, SchemaVersion: 1, ID: id, Sample: resolved, Name: workflowDisplayName(workflowType) + " · " + nameTarget, Status: status,
			CreatedAt: t, UpdatedAt: t, Options: opts,
			Metadata:  map[string]any{"source": "go-web", "execution_boundary": workflowExecutionBoundary(workflowType), "requires_confirmation": true, "workflow_type": workflowType, "workflow_params": workflowParams},
			History:   []map[string]any{{"timestamp": t, "status": status, "detail": "created"}},
			Artifacts: []map[string]any{}, Reconstruction: reconstructionState(ReconstructionState{}),
		}
		x.Orchestration = newOrchestrationState(x)
		if requestedAsset != "" && requestedAsset != "<nil>" {
			x.Metadata["requested_asset"] = requestedAsset
		}
		if provider := strings.TrimSpace(fmt.Sprint(p["provider"])); provider != "" && provider != "<nil>" {
			x.Metadata["provider"] = provider
		}
		err := s.saveExperiment(x)
		if err == nil {
			if status == "awaiting_ai_plan" {
				s.appendEvent(id, "ai_patch_plan_required", status, "已记录修改意图，等待大模型生成可审查的执行方案", map[string]any{"workflow_type": workflowType})
			} else {
				s.appendEvent(id, "queued", "queued", "任务已进入队列", nil)
			}
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
		if err == nil && (x.Status == "completed" || x.Status == "partial" || x.Status == "failed") {
			analysisRoot := filepath.Join(s.cfg.Workspace, "experiments", id, "analysis")
			x.Artifacts = s.collectArtifacts(analysisRoot)
			x.Summary = s.artifactSummary(analysisRoot)
			if x.Status == "failed" {
				if diagnostics := workerFailureDiagnostics(filepath.Join(analysisRoot, "worker-output.json")); diagnostics != "" {
					x.Error = diagnostics
				}
			}
		}
		if err == nil && x.Reconstruction.Stage == "" {
			x.Reconstruction = s.deriveLegacyReconstruction(x)
		}
		respond(w, x, err)
		return
	}
	if len(parts) == 2 && parts[1] == "orchestration" && r.Method == http.MethodGet {
		s.orchestration(w, r, id)
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
	if len(parts) == 3 && parts[1] == "source" && parts[2] == "actions" && r.Method == http.MethodPost {
		s.sourceActions(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "terminal" {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			method(w)
			return
		}
		s.terminalSessions(w, r, id)
		return
	}
	if len(parts) == 4 && parts[1] == "terminal" && parts[3] == "output" && r.Method == http.MethodGet {
		s.terminalOutput(w, r, id, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "terminal" && parts[3] == "stop" && r.Method == http.MethodPost {
		s.terminalStop(w, r, id, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "tool-calls" {
		if r.Method != http.MethodPost || (parts[3] != "retry" && parts[3] != "cancel") {
			method(w)
			return
		}
		s.toolCallAction(w, r, id, parts[2], parts[3])
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
	if len(parts) == 3 && parts[1] == "workflow" && (parts[2] == "ai-plan" || parts[2] == "ai-confirm") && r.Method == http.MethodPost {
		if parts[2] == "ai-plan" {
			s.workflowAIPlan(w, r, id)
		} else {
			s.workflowAIConfirm(w, r, id)
		}
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
		respond(w, map[string]any{"experiment": x, "running": err == nil && x.Status == "running"}, err)
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
		if rel == "." {
			return nil
		}
		if skipSourceFile(filepath.ToSlash(rel)) {
			return nil
		}
		files = append(files, map[string]any{"path": filepath.ToSlash(rel), "size": info.Size(), "editable": !info.IsDir() && sourceEditable(rel), "directory": info.IsDir(), "modified_at": info.ModTime().UTC().Format(time.RFC3339Nano)})
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

func (s *Server) sourceActions(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	var payload struct {
		Action  string   `json:"action"`
		Path    string   `json:"path"`
		Target  string   `json:"target"`
		Content string   `json:"content"`
		Paths   []string `json:"paths"`
	}
	if readJSON(r, &payload) != nil {
		bad(w, "无效的文件操作请求")
		return
	}
	action := strings.TrimSpace(strings.ToLower(payload.Action))
	if action == "" {
		bad(w, "缺少文件操作类型")
		return
	}
	applySingle := func(op string, path string, fn func(string) error) bool {
		if path == "" {
			bad(w, "缺少文件路径")
			return false
		}
		resolved, pathErr := safeProjectFile(project, path)
		if pathErr != nil {
			bad(w, pathErr.Error())
			return false
		}
		if err = fn(resolved); err != nil {
			respond(w, nil, err)
			return false
		}
		s.appendEvent(id, "source_"+op, "completed", "已执行文件操作 "+op+": "+filepath.ToSlash(path), map[string]any{"path": filepath.ToSlash(path), "target": filepath.ToSlash(payload.Target)})
		return true
	}
	applyMany := func(op string, paths []string, fn func(string) error) bool {
		if len(paths) == 0 {
			bad(w, "缺少批量文件路径")
			return false
		}
		for _, path := range paths {
			resolved, pathErr := safeProjectFile(project, path)
			if pathErr != nil {
				bad(w, pathErr.Error())
				return false
			}
			if err = fn(resolved); err != nil {
				respond(w, nil, err)
				return false
			}
		}
		s.appendEvent(id, "source_"+op, "completed", "已执行批量文件操作 "+op, map[string]any{"paths": paths, "target": filepath.ToSlash(payload.Target)})
		return true
	}
	switch action {
	case "delete":
		if !applySingle("delete", payload.Path, func(path string) error { return os.RemoveAll(path) }) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "path": filepath.ToSlash(payload.Path)})
	case "copy":
		if payload.Target == "" {
			bad(w, "缺少目标路径")
			return
		}
		if !applySingle("copy", payload.Path, func(path string) error { return copyProjectPath(project, path, payload.Target) }) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"copied": true, "path": filepath.ToSlash(payload.Path), "target": filepath.ToSlash(payload.Target)})
	case "move":
		if payload.Target == "" {
			bad(w, "缺少目标路径")
			return
		}
		if !applySingle("move", payload.Path, func(path string) error { return moveProjectPath(project, path, payload.Target) }) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"moved": true, "path": filepath.ToSlash(payload.Path), "target": filepath.ToSlash(payload.Target)})
	case "mkdir":
		if payload.Path == "" {
			bad(w, "缺少目录路径")
			return
		}
		resolved, pathErr := safeProjectFile(project, payload.Path)
		if pathErr != nil {
			bad(w, pathErr.Error())
			return
		}
		if err = os.MkdirAll(resolved, 0755); err != nil {
			respond(w, nil, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"created": true, "path": filepath.ToSlash(payload.Path)})
	case "write":
		if payload.Path == "" {
			bad(w, "缺少文件路径")
			return
		}
		resolved, pathErr := safeProjectFile(project, payload.Path)
		if pathErr != nil {
			bad(w, pathErr.Error())
			return
		}
		if err = os.MkdirAll(filepath.Dir(resolved), 0755); err != nil {
			respond(w, nil, err)
			return
		}
		if err = os.WriteFile(resolved, []byte(payload.Content), 0600); err != nil {
			respond(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"written": true, "path": filepath.ToSlash(payload.Path), "size": len(payload.Content)})
	case "batch-delete":
		if !applyMany("batch_delete", payload.Paths, func(path string) error { return os.RemoveAll(path) }) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "count": len(payload.Paths)})
	case "batch-copy":
		if payload.Target == "" {
			bad(w, "缺少目标目录")
			return
		}
		if !applyMany("batch_copy", payload.Paths, func(path string) error { return copyProjectPath(project, path, payload.Target) }) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"copied": true, "count": len(payload.Paths), "target": filepath.ToSlash(payload.Target)})
	case "batch-move":
		if payload.Target == "" {
			bad(w, "缺少目标目录")
			return
		}
		if !applyMany("batch_move", payload.Paths, func(path string) error { return moveProjectPath(project, path, payload.Target) }) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"moved": true, "count": len(payload.Paths), "target": filepath.ToSlash(payload.Target)})
	default:
		bad(w, "不支持的文件操作类型")
	}
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
		if walkErr != nil || info.IsDir() || strings.Contains(filepath.ToSlash(path), "/.build/") || skipSourceFile(filepath.ToSlash(path)) {
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

func (s *Server) terminalSessions(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		items := []map[string]any{}
		for _, session := range s.terminals {
			if session.ExperimentID != id {
				continue
			}
			session.Mu.Lock()
			items = append(items, terminalSessionView(session))
			session.Mu.Unlock()
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": items})
		return
	}
	var payload struct {
		Command string `json:"command"`
	}
	if readJSON(r, &payload) != nil || strings.TrimSpace(payload.Command) == "" {
		bad(w, "请输入终端命令")
		return
	}
	session := &terminalSession{ID: newID(), ExperimentID: id, Command: strings.TrimSpace(payload.Command), StartedAt: now(), Status: "running"}
	ctx, cancel := context.WithCancel(context.Background())
	session.Cancel = cancel
	var execution workerExecution
	if s.cfg.Production || s.cfg.RunnerURL != "" {
		relativeProject, relErr := filepath.Rel(s.cfg.Workspace, project)
		if relErr != nil || relativeProject == ".." || strings.HasPrefix(relativeProject, ".."+string(filepath.Separator)) {
			cancel()
			bad(w, "源码工程不在共享工作区")
			return
		}
		execution, err = s.startRunnerJob(ctx, runnerJobRequest{Kind: "terminal", Project: filepath.ToSlash(relativeProject), Command: session.Command})
	} else {
		cmd := exec.CommandContext(ctx, "cmd", "/c", session.Command)
		if runtime.GOOS != "windows" {
			cmd = exec.CommandContext(ctx, "bash", "-lc", session.Command)
		}
		cmd.Dir = project
		stdout, pipeErr := cmd.StdoutPipe()
		if pipeErr == nil {
			cmd.Stderr = cmd.Stdout
			pipeErr = cmd.Start()
		}
		if pipeErr == nil {
			session.Cmd = cmd
			execution = workerExecution{Output: stdout, Wait: cmd.Wait}
		}
		err = pipeErr
	}
	if err != nil {
		cancel()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "dependency-gated", "error": err.Error()})
		return
	}
	s.terminals[session.ID] = session
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		defer execution.Output.Close()
		scanner := bufio.NewScanner(execution.Output)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		eventLines := 0
		eventTruncated := false
		for scanner.Scan() {
			line := scanner.Text()
			session.Mu.Lock()
			appendTerminalOutput(session, line)
			session.Mu.Unlock()
			if eventLines < terminalEventLines {
				s.appendEvent(id, "terminal_output", "running", line, map[string]any{"session_id": session.ID})
				eventLines++
			} else if !eventTruncated {
				eventTruncated = true
				s.appendEvent(id, "terminal_output_truncated", "running", "终端事件输出已截断，完整尾部请读取会话输出", map[string]any{"session_id": session.ID, "event_line_limit": terminalEventLines})
			}
		}
		waitErr := execution.Wait()
		session.Mu.Lock()
		if session.Status != "stopped" {
			exitCode := 0
			if waitErr != nil {
				session.Status = "failed"
				session.Error = waitErr.Error()
				exitCode = 1
				var exitError *exec.ExitError
				if errors.As(waitErr, &exitError) {
					exitCode = exitError.ExitCode()
				}
			} else {
				session.Status = "finished"
			}
			session.ExitCode = &exitCode
			session.EndedAt = now()
		}
		status := session.Status
		session.Mu.Unlock()
		s.scheduleTerminalCleanup(session.ID)
		eventStatus := "completed"
		message := "终端会话已结束"
		if status == "failed" {
			eventStatus = "failed"
			message = "终端会话执行失败"
		}
		s.appendEvent(id, "terminal_closed", eventStatus, message, map[string]any{"session_id": session.ID})
	}()
	writeJSON(w, http.StatusCreated, map[string]any{"session": map[string]any{"id": session.ID, "command": session.Command, "status": session.Status, "started_at": session.StartedAt}})
}

func (s *Server) terminalOutput(w http.ResponseWriter, r *http.Request, id, sessionID string) {
	if _, err := s.findSourceProject(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	session := s.terminals[sessionID]
	s.mu.Unlock()
	if session == nil || session.ExperimentID != id {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "终端会话不存在"})
		return
	}
	session.Mu.Lock()
	defer session.Mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"session": terminalSessionView(session), "output": session.Output})
}

func (s *Server) terminalStop(w http.ResponseWriter, r *http.Request, id, sessionID string) {
	s.mu.Lock()
	session := s.terminals[sessionID]
	s.mu.Unlock()
	if session == nil || session.ExperimentID != id {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "终端会话不存在"})
		return
	}
	session.Mu.Lock()
	if session.Cancel != nil {
		session.Cancel()
	}
	if session.Status == "running" {
		exitCode := -1
		session.Status = "stopped"
		session.ExitCode = &exitCode
		session.EndedAt = now()
	}
	session.Mu.Unlock()
	s.scheduleTerminalCleanup(sessionID)
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true, "session_id": sessionID})
}

func appendTerminalOutput(session *terminalSession, line string) {
	entryBytes := len(line) + 1
	for len(session.Output) > 0 && (len(session.Output) >= terminalMaxLines || session.OutputBytes+entryBytes > terminalMaxBytes) {
		oldest := fmt.Sprint(session.Output[0]["line"])
		session.Output = session.Output[1:]
		session.OutputBytes -= len(oldest) + 1
		session.DroppedLines++
		session.Truncated = true
	}
	if entryBytes > terminalMaxBytes {
		line = line[len(line)-terminalMaxBytes+1:]
		entryBytes = len(line) + 1
		session.DroppedLines++
		session.Truncated = true
	}
	session.Output = append(session.Output, map[string]any{"timestamp": now(), "line": line})
	session.OutputBytes += entryBytes
}

func terminalSessionView(session *terminalSession) map[string]any {
	return map[string]any{
		"id": session.ID, "command": session.Command, "status": session.Status,
		"started_at": session.StartedAt, "ended_at": session.EndedAt,
		"exit_code": session.ExitCode, "error": session.Error,
		"output_count": len(session.Output), "output_bytes": session.OutputBytes,
		"dropped_lines": session.DroppedLines, "truncated": session.Truncated,
	}
}

func (s *Server) scheduleTerminalCleanup(sessionID string) {
	time.AfterFunc(terminalSessionTTL, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		session := s.terminals[sessionID]
		if session == nil {
			return
		}
		session.Mu.Lock()
		endedAt, err := time.Parse(time.RFC3339Nano, session.EndedAt)
		finished := session.Status != "running" && err == nil && time.Since(endedAt) >= terminalSessionTTL
		session.Mu.Unlock()
		if finished {
			delete(s.terminals, sessionID)
		}
	})
}

var (
	errToolCallNotFound = errors.New("工具调用不存在")
	errToolCallConflict = errors.New("工具调用状态不允许此操作")
)

func defaultToolCallExecutors() map[string]toolCallExecutor {
	return map[string]toolCallExecutor{}
}

func normalizeToolCall(call *OrchestrationToolCall) {
	if call.RootID == "" {
		call.RootID = call.ID
	}
	if call.Attempt <= 0 {
		call.Attempt = 1
	}
}

func toolCallExecutionKey(experimentID, toolCallID string) string {
	return experimentID + ":" + toolCallID
}

func (s *Server) mutateExperiment(id string, mutate func(*Experiment) error) (Experiment, error) {
	if s.dbErr != nil {
		return Experiment{}, s.dbErr
	}
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return Experiment{}, err
		}
		defer tx.Rollback()
		var payload []byte
		if err = tx.QueryRow(`SELECT payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&payload); err != nil {
			return Experiment{}, err
		}
		var experiment Experiment
		if err = json.Unmarshal(payload, &experiment); err != nil {
			return Experiment{}, err
		}
		if err = mutate(&experiment); err != nil {
			return Experiment{}, err
		}
		payload, err = json.Marshal(experiment)
		if err != nil {
			return Experiment{}, err
		}
		result, err := tx.Exec(`UPDATE experiments SET status=$1,updated_at=$2,payload=$3::jsonb WHERE id=$4 AND workspace_id=$5`, experiment.Status, experiment.UpdatedAt, string(payload), id, s.cfg.Workspace)
		if err != nil {
			return Experiment{}, err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return Experiment{}, errors.New("experiment update was not applied")
		}
		if err = tx.Commit(); err != nil {
			return Experiment{}, err
		}
		return experiment, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var experiment Experiment
	if err := readFileJSON(s.experimentPath(id), &experiment); err != nil {
		return Experiment{}, err
	}
	if err := mutate(&experiment); err != nil {
		return Experiment{}, err
	}
	if err := writeFileJSON(s.experimentPath(id), experiment); err != nil {
		return Experiment{}, err
	}
	return experiment, nil
}

func (s *Server) toolCallAction(w http.ResponseWriter, r *http.Request, id, toolID, action string) {
	if action != "retry" && action != "cancel" {
		bad(w, "不支持的工具调用操作")
		return
	}
	nowStr := now()
	var source OrchestrationToolCall
	var successor OrchestrationToolCall
	experiment, err := s.mutateExperiment(id, func(experiment *Experiment) error {
		if experiment.Orchestration == nil {
			experiment.Orchestration = newOrchestrationState(*experiment)
		}
		var call *OrchestrationToolCall
		for idx := range experiment.Orchestration.ToolCalls {
			candidate := &experiment.Orchestration.ToolCalls[idx]
			normalizeToolCall(candidate)
			if candidate.ID == toolID {
				call = candidate
			}
		}
		if call == nil {
			return errToolCallNotFound
		}
		source = *call
		switch action {
		case "retry":
			if call.Status != "failed" && call.Status != "cancelled" && call.Status != "dependency-gated" {
				return fmt.Errorf("%w: 只有失败、已取消或依赖受限的调用可以重试", errToolCallConflict)
			}
			successor = OrchestrationToolCall{
				ID: newID(), RootID: call.RootID, Attempt: call.Attempt + 1, RetryOf: call.ID,
				Name: call.Name, Status: "queued", Result: "已创建重试 attempt，等待执行",
				Timestamp: nowStr, Args: call.Args,
			}
			if _, replayable := s.toolExecutors[call.Name]; !replayable {
				successor.Status = "dependency-gated"
				successor.EndedAt = nowStr
				successor.Result = "该历史工具调用未注册安全重放执行器"
			}
			experiment.Orchestration.ToolCalls = append(experiment.Orchestration.ToolCalls, successor)
		case "cancel":
			if call.Status != "queued" && call.Status != "running" {
				return fmt.Errorf("%w: 只有排队中或运行中的调用可以取消", errToolCallConflict)
			}
			call.Status = "cancelled"
			call.Canceled = true
			call.EndedAt = nowStr
			if call.StartedAt != "" {
				call.Duration = durationSince(call.StartedAt, nowStr)
			}
			call.Result = "已取消"
			source = *call
		}
		experiment.UpdatedAt = nowStr
		experiment.Orchestration.UpdatedAt = nowStr
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errToolCallNotFound), errors.Is(err, sql.ErrNoRows), os.IsNotExist(err):
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "工具调用不存在"})
		case errors.Is(err, errToolCallConflict):
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		default:
			respond(w, nil, err)
		}
		return
	}
	if action == "cancel" {
		s.mu.Lock()
		if cancel := s.toolRunning[toolCallExecutionKey(id, toolID)]; cancel != nil {
			cancel()
		}
		s.mu.Unlock()
		s.appendEvent(id, "tool_call_cancel", "cancelled", "工具调用 attempt 已取消", map[string]any{"tool_call_id": toolID, "root_id": source.RootID, "attempt": source.Attempt})
		writeJSON(w, http.StatusOK, map[string]any{"tool_call": source, "action": action, "saved": true})
		return
	}
	s.appendEvent(id, "tool_call_retry", successor.Status, "已创建工具调用 successor attempt", map[string]any{"tool_call_id": successor.ID, "retry_of": source.ID, "root_id": successor.RootID, "attempt": successor.Attempt})
	if successor.Status == "queued" {
		s.startToolCallAttempt(experiment, successor)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tool_call": successor, "action": action, "saved": true})
}

func (s *Server) startToolCallAttempt(experiment Experiment, call OrchestrationToolCall) {
	executor := s.toolExecutors[call.Name]
	if executor == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	key := toolCallExecutionKey(experiment.ID, call.ID)
	s.mu.Lock()
	s.toolRunning[key] = cancel
	s.mu.Unlock()
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		defer func() {
			s.mu.Lock()
			delete(s.toolRunning, key)
			s.mu.Unlock()
			cancel()
		}()
		startedAt := now()
		started := false
		_, err := s.mutateExperiment(experiment.ID, func(current *Experiment) error {
			if current.Orchestration == nil {
				return nil
			}
			for idx := range current.Orchestration.ToolCalls {
				candidate := &current.Orchestration.ToolCalls[idx]
				if candidate.ID != call.ID || candidate.Status != "queued" {
					continue
				}
				candidate.Status = "running"
				candidate.StartedAt = startedAt
				candidate.Result = "执行中"
				current.UpdatedAt = startedAt
				current.Orchestration.UpdatedAt = startedAt
				started = true
				break
			}
			return nil
		})
		if err != nil || !started {
			return
		}
		s.appendEvent(experiment.ID, "tool_call_started", "running", "工具调用 attempt 开始执行", map[string]any{"tool_call_id": call.ID, "root_id": call.RootID, "attempt": call.Attempt})
		result, executeErr := executor(ctx, experiment, call)
		endedAt := now()
		terminalStatus := "completed"
		if ctx.Err() != nil {
			terminalStatus = "cancelled"
			result = "已取消"
		} else if executeErr != nil {
			terminalStatus = "failed"
			result = executeErr.Error()
		}
		updated := false
		_, err = s.mutateExperiment(experiment.ID, func(current *Experiment) error {
			if current.Orchestration == nil {
				return nil
			}
			for idx := range current.Orchestration.ToolCalls {
				candidate := &current.Orchestration.ToolCalls[idx]
				if candidate.ID != call.ID || candidate.Status != "running" {
					continue
				}
				candidate.Status = terminalStatus
				candidate.Canceled = terminalStatus == "cancelled"
				candidate.Result = result
				candidate.EndedAt = endedAt
				candidate.Duration = durationSince(candidate.StartedAt, endedAt)
				current.UpdatedAt = endedAt
				current.Orchestration.UpdatedAt = endedAt
				updated = true
				break
			}
			return nil
		})
		if err == nil && updated {
			s.appendEvent(experiment.ID, "tool_call_finished", terminalStatus, "工具调用 attempt 已结束", map[string]any{"tool_call_id": call.ID, "root_id": call.RootID, "attempt": call.Attempt})
		}
	}()
}

func (s *Server) buildSourceProject(w http.ResponseWriter, r *http.Request, id string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	buildDir := filepath.Join(project, ".build")
	_ = os.MkdirAll(buildDir, 0755)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	output := &limitedWriter{remaining: 2 << 20}
	isolation := "local-container"
	s.appendEvent(id, "build_started", "running", "开始构建重构源码工程", map[string]any{"isolated": true, "isolation": isolation})
	if s.cfg.Production || s.cfg.RunnerURL != "" {
		relativeProject, relErr := filepath.Rel(s.cfg.Workspace, project)
		if relErr != nil || relativeProject == ".." || strings.HasPrefix(relativeProject, ".."+string(filepath.Separator)) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "源码工程不在共享工作区"})
			return
		}
		var execution workerExecution
		execution, err = s.startRunnerJob(ctx, runnerJobRequest{Kind: "build", Project: filepath.ToSlash(relativeProject)})
		if err == nil {
			isolation = "remote-runner"
			_, err = io.Copy(output, execution.Output)
			closeErr := execution.Output.Close()
			waitErr := execution.Wait()
			err = errors.Join(err, closeErr, waitErr)
		}
	} else {
		if _, err = exec.LookPath("cmake"); err == nil {
			isolated, mode := buildIsolation()
			if !isolated {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "dependency-gated", "error": "真实构建必须在独立 runner 或明确配置的本地测试环境中执行", "isolation": mode})
				return
			}
			isolation = mode
			for _, args := range [][]string{{"-S", project, "-B", buildDir}, {"--build", buildDir, "--config", "Release"}} {
				cmd := exec.CommandContext(ctx, "cmake", args...)
				cmd.Dir = project
				cmd.Stdout, cmd.Stderr = output, output
				if err = cmd.Run(); err != nil {
					break
				}
			}
		}
	}
	if err != nil && output.buf.Len() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "dependency-gated", "error": err.Error(), "isolation": isolation})
		return
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
	project, err := filepath.Abs(project)
	if err != nil {
		return "", err
	}
	realProject, err := filepath.EvalSymlinks(project)
	if err != nil {
		return "", fmt.Errorf("源码工程真实路径不可用: %w", err)
	}
	path := filepath.Join(project, filepath.FromSlash(requested))
	path, err = filepath.Abs(path)
	if err != nil || !pathWithin(project, path) {
		return "", errors.New("源码路径超出重构工程")
	}
	ancestor := path
	for {
		info, statErr := os.Lstat(ancestor)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("源码路径不允许经过符号链接或重解析点")
			}
			break
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor || !pathWithin(project, parent) {
			return "", errors.New("源码路径超出重构工程")
		}
		ancestor = parent
	}
	realAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil || !pathWithin(realProject, realAncestor) {
		return "", errors.New("源码路径真实位置超出重构工程")
	}
	return path, nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sourceEditable(path string) bool {
	name := filepath.Base(path)
	extension := strings.ToLower(filepath.Ext(name))
	return name == "CMakeLists.txt" || map[string]bool{".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true, ".md": true, ".py": true, ".java": true, ".kt": true, ".smali": true, ".xml": true, ".json": true, ".js": true, ".ts": true, ".html": true, ".css": true, ".gradle": true, ".properties": true, ".txt": true}[extension]
}

func skipSourceFile(path string) bool {
	base := filepath.Base(path)
	return base == "SOURCE_TREE.json" || base == "BUILD_STATUS.json"
}

func copyProjectPath(project, sourcePath, target string) error {
	dest, err := safeProjectFile(project, target)
	if err != nil {
		return err
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return filepath.Walk(sourcePath, func(path string, fileInfo os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fileInfo.Mode()&os.ModeSymlink != 0 {
				return errors.New("不允许复制包含符号链接或重解析点的源码目录")
			}
			rel, relErr := filepath.Rel(sourcePath, path)
			if relErr != nil {
				return relErr
			}
			out := filepath.Join(dest, rel)
			if fileInfo.IsDir() {
				return os.MkdirAll(out, 0755)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
				return err
			}
			return os.WriteFile(out, data, 0600)
		})
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0600)
}

func moveProjectPath(project, sourcePath, target string) error {
	dest, err := safeProjectFile(project, target)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	return os.Rename(sourcePath, dest)
}

func durationSince(startedAt, endedAt string) string {
	start, err1 := time.Parse(time.RFC3339Nano, startedAt)
	end, err2 := time.Parse(time.RFC3339Nano, endedAt)
	if err1 != nil || err2 != nil {
		return ""
	}
	return end.Sub(start).String()
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

func normalizeWorkflowType(raw string) (string, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" || value == "<nil>" {
		return "reverse_analysis", nil
	}
	switch value {
	case "reverse_analysis", "authorized_pentest", "binary_patch", "memory_patch", "process_injection":
		return value, nil
	default:
		return "", errors.New("不支持的作业类型")
	}
}

func workflowTypeOf(experiment Experiment) string {
	workflow, _ := normalizeWorkflowType(fmt.Sprint(experiment.Metadata["workflow_type"]))
	return workflow
}

func workflowDisplayName(workflow string) string {
	return map[string]string{
		"reverse_analysis":   "逆向分析",
		"authorized_pentest": "授权渗透计划",
		"binary_patch":       "二进制补丁",
		"memory_patch":       "动态内存补丁",
		"process_injection":  "进程内注入",
	}[workflow]
}

func workflowPlanConfirmed(experiment Experiment) bool {
	params, ok := experiment.Metadata["workflow_params"].(map[string]any)
	if !ok || fmt.Sprint(params["plan_status"]) != "confirmed" || strings.TrimSpace(fmt.Sprint(params["plan_id"])) == "" {
		return false
	}
	return true
}

func workflowExecutionBoundary(workflow string) string {
	if workflow == "authorized_pentest" {
		return "plan-only"
	}
	if workflow == "memory_patch" || workflow == "process_injection" {
		return "windows-local-operator"
	}
	return "isolated-worker"
}

func workflowStages(workflow string) [][2]string {
	switch workflow {
	case "authorized_pentest":
		return [][2]string{{"范围与目标建模", "记录目标、范围和可用接口，生成可审计工作流计划"}, {"技能与工具路由", "按目标类型选择已注册的本地技能和工具依赖"}, {"执行前复核", "等待操作人员在具备对应执行器后提交确认"}}
	case "binary_patch":
		return [][2]string{{"二进制证据", "读取目标身份、偏移和预映像字节"}, {"补丁计划", "生成等长替换计划并验证前置条件"}, {"副本验证与回滚", "在独立输出副本上验证结果并保留回滚证据"}}
	case "memory_patch":
		return [][2]string{{"进程身份与读前证据", "校验 PID、映像身份和目标地址预映像"}, {"受控内存写入", "通过 memory_runtime 执行带预条件的写入"}, {"结果验证与回滚", "记录执行证据并按请求执行回滚验证"}}
	case "process_injection":
		return [][2]string{{"进程与 DLL 身份", "校验 PID、DLL 哈希和体系结构兼容性"}, {"受控注入计划", "生成 LoadLibrary 或 manual map 的可审计计划"}, {"执行证据与清理", "收集注入结果、回滚和清理证据"}}
	default:
		return [][2]string{{"证据与静态分析", "收集目标文件、字符串、导入和基础分析证据"}, {"语义与源码重构", "生成语义中间表示和可编辑源码工程"}, {"构建与行为验证", "验证重构工程的构建和行为等价性"}}
	}
}

func (s *Server) workflowParameters(workflow string, payload map[string]any) (map[string]any, error) {
	params := map[string]any{}
	field := func(name string, required bool) (string, error) {
		value := strings.TrimSpace(fmt.Sprint(payload[name]))
		if value == "<nil>" {
			value = ""
		}
		if len(value) > 4000 {
			return "", fmt.Errorf("%s 不能超过 4000 个字符", name)
		}
		if required && value == "" {
			return "", fmt.Errorf("%s 不能为空", name)
		}
		return value, nil
	}
	switch workflow {
	case "authorized_pentest":
		objective, err := field("objective", true)
		if err != nil {
			return nil, errors.New("授权渗透计划需要测试目标")
		}
		endpoint, err := field("endpoint", true)
		if err != nil {
			return nil, errors.New("授权渗透计划需要域名或 URL")
		}
		scope, err := field("authorization_scope", true)
		if err != nil {
			return nil, errors.New("授权渗透计划需要明确授权范围")
		}
		params["objective"] = objective
		params["endpoint"] = endpoint
		params["authorization_scope"] = scope
		if contextInfo, _ := field("context", false); contextInfo != "" {
			params["context"] = contextInfo
		}
	case "binary_patch", "memory_patch", "process_injection":
		instruction, err := field("instruction", true)
		if err != nil || len([]rune(instruction)) < 4 {
			return nil, errors.New("补丁作业需要至少 4 个字符的修改需求")
		}
		params["instruction"] = instruction
		params["plan_status"] = "required"
		if constraints, _ := field("constraints", false); constraints != "" {
			params["constraints"] = constraints
		}
		if validation, _ := field("validation_requirements", false); validation != "" {
			params["validation_requirements"] = validation
		}
		if workflow == "memory_patch" || workflow == "process_injection" {
			targetProcess, targetErr := field("target_process", true)
			authorization, authorizationErr := field("authorization_statement", true)
			if targetErr != nil || authorizationErr != nil || len([]rune(authorization)) < 4 {
				return nil, errors.New("动态进程作业需要目标进程说明和明确授权依据")
			}
			params["target_process"] = targetProcess
			params["authorization_statement"] = authorization
		}
		if workflow == "process_injection" {
			if moduleSource, _ := field("module_source", false); moduleSource != "" {
				params["module_source"] = moduleSource
			}
		}
	}
	return params, nil
}

func validateAuthorizedEndpoint(target, endpoint string) error {
	value := strings.TrimSpace(endpoint)
	if value == "" || value == "<nil>" {
		value = strings.TrimSpace(target)
	}
	if value == "" || value == "<nil>" || len(value) > 2048 || strings.IndexAny(value, " \r\n\t") >= 0 {
		return errors.New("授权渗透计划需要有效的域名或 HTTP(S) URL")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return errors.New("授权渗透计划只接受有效的域名或 HTTP(S) URL")
	}
	return nil
}

func (s *Server) resolveWorkflowPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == "<nil>" {
		return "", errors.New("invalid path")
	}
	return s.safePath(value)
}

func newOrchestrationState(experiment Experiment) *OrchestrationState {
	stages := workflowStages(workflowTypeOf(experiment))
	subtasks := make([]OrchestrationSubtask, 0, len(stages))
	for index, stage := range stages {
		subtasks = append(subtasks, OrchestrationSubtask{
			ID: experiment.ID + "-subtask-" + strconv.Itoa(index+1), TaskID: experiment.ID,
			Title: stage[0], Description: stage[1], Status: "waiting", Result: "等待执行",
		})
	}
	return &OrchestrationState{
		Version:  1,
		Flow:     OrchestrationFlow{ID: experiment.ID, Title: experiment.Name, Status: experiment.Status, CreatedAt: experiment.CreatedAt, UpdatedAt: experiment.UpdatedAt},
		Tasks:    []OrchestrationTask{{ID: experiment.ID, Title: experiment.Name, Status: experiment.Status, Input: experiment.Sample, Result: orchestrationResult(experiment)}},
		Subtasks: subtasks, ToolCalls: []OrchestrationToolCall{}, UpdatedAt: experiment.UpdatedAt,
	}
}

func (s *Server) ensureOrchestrationState(experiment Experiment, events []Event) Experiment {
	if experiment.Orchestration == nil {
		experiment.Orchestration = newOrchestrationState(experiment)
	}
	state := experiment.Orchestration
	for idx := range state.ToolCalls {
		normalizeToolCall(&state.ToolCalls[idx])
	}
	state.Flow.Status = experiment.Status
	state.Flow.Title = experiment.Name
	state.Flow.UpdatedAt = experiment.UpdatedAt
	if len(state.Tasks) == 0 {
		state.Tasks = newOrchestrationState(experiment).Tasks
	}
	state.Tasks[0].Status = experiment.Status
	state.Tasks[0].Title = experiment.Name
	state.Tasks[0].Input = experiment.Sample
	state.Tasks[0].Result = orchestrationResult(experiment)
	for _, event := range events {
		if event.Sequence <= state.LastEventSequence {
			continue
		}
		applyOrchestrationEvent(state, event)
		state.LastEventSequence = event.Sequence
	}
	state.UpdatedAt = experiment.UpdatedAt
	return experiment
}

func applyOrchestrationEvent(state *OrchestrationState, event Event) {
	if state == nil || len(state.Subtasks) < 3 {
		return
	}
	if strings.HasPrefix(event.Type, "tool_call_") {
		return
	}
	setSubtask := func(index int, status, result string) {
		state.Subtasks[index].Status = status
		state.Subtasks[index].Result = result
		state.Subtasks[index].UpdatedAt = event.Timestamp
	}
	finishBefore := func(index int, result string) {
		for current := 0; current < index; current++ {
			if state.Subtasks[current].Status == "waiting" || state.Subtasks[current].Status == "running" {
				setSubtask(current, "finished", result)
			}
		}
	}
	containsAny := func(values ...string) bool {
		for _, value := range values {
			if strings.Contains(event.Type, value) {
				return true
			}
		}
		return false
	}
	switch {
	case event.Type == "queued":
		setSubtask(0, "waiting", "等待执行")
	case event.Type == "execution_confirmed":
		setSubtask(0, "running", event.Message)
	case event.Type == "started" || event.Type == "progress" || event.Type == "provider_broker_started" || event.Type == "provider_fallback":
		setSubtask(0, "running", event.Message)
	case event.Type == "result_summary":
		setSubtask(0, "finished", event.Message)
		setSubtask(1, "running", state.Subtasks[1].Title+"进行中")
	case event.Type == "project_readiness" || strings.HasPrefix(event.Type, "model_") || event.Type == "model_reconstruction_recorded":
		finishBefore(1, "前置证据已记录")
		setSubtask(1, "running", event.Message)
	case event.Type == "build_started" || strings.HasPrefix(event.Type, "automated_build") || event.Type == "build_repair_recorded" || strings.HasPrefix(event.Type, "patch_") || containsAny("memory_runtime", "injector"):
		finishBefore(2, "前置阶段已完成")
		setSubtask(2, "running", event.Message)
	case event.Type == "build_completed" || strings.HasPrefix(event.Type, "behavior_") || event.Type == "behavior_repair_recorded":
		finishBefore(2, "前置阶段已完成")
		setSubtask(2, event.Status, event.Message)
	case event.Status == "completed" && (strings.HasPrefix(event.Type, "patch_") || containsAny("memory_runtime", "injector")):
		finishBefore(2, "前置阶段已完成")
		setSubtask(2, "finished", event.Message)
	case event.Status == "failed" || event.Status == "cancelled":
		for index := range state.Subtasks {
			if state.Subtasks[index].Status == "running" {
				setSubtask(index, event.Status, event.Message)
			}
		}
	}
	controlEvent := strings.HasPrefix(event.Type, "tool_call_")
	if !controlEvent && (strings.Contains(event.Type, "model") || strings.Contains(event.Type, "provider") || strings.Contains(event.Type, "tool") || strings.Contains(event.Type, "memory_runtime") || strings.Contains(event.Type, "injector")) {
		toolCallID := fmt.Sprintf("%s-tool-%d", state.Flow.ID, event.Sequence)
		state.ToolCalls = append(state.ToolCalls, OrchestrationToolCall{
			ID:        toolCallID,
			RootID:    toolCallID,
			Attempt:   1,
			Name:      event.Type,
			Status:    event.Status,
			Result:    event.Message,
			Timestamp: event.Timestamp,
			StartedAt: event.Timestamp,
			EndedAt:   event.Timestamp,
			Duration:  "0s",
			Args:      event.Data,
		})
	}
}

func (s *Server) persistOrchestrationEvent(id string, event Event) {
	experiment, err := s.loadExperiment(id)
	if err != nil {
		return
	}
	experiment = s.ensureOrchestrationState(experiment, []Event{event})
	if err := s.saveExperiment(experiment); err != nil {
		log.Printf("persist orchestration state failed for experiment %s: %v", id, err)
	}
}

func (s *Server) orchestration(w http.ResponseWriter, r *http.Request, id string) {
	experiment, err := s.loadExperiment(id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	events, err := s.events(id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	root := filepath.Join(s.cfg.Workspace, "experiments", id, "analysis")
	files := s.orchestrationFiles(root)
	state := s.ensureOrchestrationState(experiment, events).Orchestration
	logs := []map[string]any{}
	for _, event := range events {
		logs = append(logs, map[string]any{
			"id": fmt.Sprintf("%s-%d", id, event.Sequence), "type": orchestrationLogType(event.Type),
			"message": event.Message, "status": event.Status, "timestamp": event.Timestamp,
		})
	}
	if state == nil {
		state = newOrchestrationState(experiment)
	}
	flow := map[string]any{"id": state.Flow.ID, "title": state.Flow.Title, "status": state.Flow.Status, "created_at": state.Flow.CreatedAt, "updated_at": state.Flow.UpdatedAt}
	writeJSON(w, http.StatusOK, map[string]any{
		"flow": flow, "tasks": state.Tasks, "subtasks": state.Subtasks,
		"tool_calls": state.ToolCalls, "logs": logs, "files": files,
		"generated_at": now(),
	})
}

func orchestrationLogType(eventType string) string {
	switch {
	case eventType == "output" || strings.Contains(eventType, "terminal"):
		return "terminal"
	case strings.Contains(eventType, "model") || strings.Contains(eventType, "provider") || strings.Contains(eventType, "tool"):
		return "tool"
	case strings.Contains(eventType, "build") || strings.Contains(eventType, "behavior") || strings.Contains(eventType, "validation"):
		return "validation"
	default:
		return "message"
	}
}

func orchestrationResult(experiment Experiment) string {
	if experiment.Error != "" {
		return experiment.Error
	}
	if experiment.Summary != nil {
		return "分析结果已归档"
	}
	return statusText(experiment.Status)
}

func getOrchestrationToolCallDuration(startedAt, endedAt string) string {
	if startedAt == "" || endedAt == "" {
		return ""
	}
	start, err1 := time.Parse(time.RFC3339Nano, startedAt)
	end, err2 := time.Parse(time.RFC3339Nano, endedAt)
	if err1 != nil || err2 != nil {
		return ""
	}
	return end.Sub(start).String()
}

func statusText(value string) string {
	return map[string]string{"queued": "已排队", "planned": "已计划", "running": "运行中", "completed": "已完成", "partial": "部分完成", "failed": "失败", "cancelled": "已取消"}[value]
}

func orchestrationStages(experiment Experiment, events []Event, sourceGenerated bool) [][4]string {
	stages := [][4]string{
		{"证据与静态分析", "收集目标文件、字符串、导入和基础分析证据", "waiting", "等待执行"},
		{"语义与源码重构", "生成语义中间表示和可编辑源码工程", "waiting", "等待前置阶段"},
		{"构建与行为验证", "验证重构工程的构建和行为等价性", "waiting", "等待前置阶段"},
	}
	if experiment.Status == "queued" || experiment.Status == "planned" {
		return stages
	}
	stages[0][2], stages[0][3] = "finished", "分析证据已记录"
	if sourceGenerated {
		stages[1][2], stages[1][3] = "finished", "源码工程已生成"
	} else if experiment.Status == "running" {
		stages[1][2], stages[1][3] = "running", "源码重构阶段进行中"
	}
	if experiment.Reconstruction.CompleteBuildable {
		stages[2][2], stages[2][3] = "finished", "构建与行为验证均通过"
	} else if experiment.Reconstruction.BuildPassed || experiment.Reconstruction.BehaviorPassed || hasEventType(events, "project_readiness") {
		stages[2][2], stages[2][3] = "running", "部分验证证据已记录"
	} else if experiment.Status == "failed" || experiment.Status == "partial" {
		stages[2][2], stages[2][3] = "failed", "验证门禁尚未全部通过"
	}
	return stages
}

func hasEventType(events []Event, kind string) bool {
	for _, event := range events {
		if event.Type == kind {
			return true
		}
	}
	return false
}

func (s *Server) orchestrationFiles(root string) []map[string]any {
	files := []map[string]any{}
	if _, err := os.Stat(root); err != nil {
		return files
	}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() || len(files) >= 500 {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/.build/") || strings.Contains(filepath.ToSlash(path), "/CMakeFiles/") {
			return nil
		}
		rel, err := filepath.Rel(s.cfg.Workspace, path)
		if err != nil {
			return nil
		}
		files = append(files, map[string]any{"id": filepath.ToSlash(rel), "name": info.Name(), "path": filepath.ToSlash(rel), "size": info.Size(), "is_dir": false, "modified_at": info.ModTime().UTC().Format(time.RFC3339Nano)})
		return nil
	})
	return files
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
	var x Experiment
	var eventData map[string]any
	if s.db != nil {
		tx, txErr := s.db.BeginTx(r.Context(), nil)
		if txErr != nil {
			return x, txErr
		}
		defer tx.Rollback()
		if txErr = s.setAuditTransactionContext(tx, r, who, "experiment.execute"); txErr != nil {
			return x, txErr
		}
		var payload []byte
		if txErr = tx.QueryRowContext(r.Context(), `SELECT payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&payload); txErr != nil {
			return x, txErr
		}
		if txErr = json.Unmarshal(payload, &x); txErr != nil {
			return x, txErr
		}
		if x.Status != "queued" && x.Status != "planned" {
			return x, errors.New("only queued or planned jobs can run")
		}
		workflow := workflowTypeOf(x)
		if (workflow == "memory_patch" || workflow == "process_injection") && !workflowPlanConfirmed(x) {
			return x, errors.New("动态补丁必须先完成 AI 方案生成、审查和人工确认")
		}
		if workflowExecutionBoundary(workflow) == "plan-only" {
			if x.Metadata == nil {
				x.Metadata = map[string]any{}
			}
			confirmedAt := now()
			x.Metadata["execution_confirmation"] = map[string]any{"actor": who.Subject, "role": who.Role, "timestamp": confirmedAt, "source": who.Source}
			x = s.status(x, "planned", "已确认授权渗透计划，等待具备执行器后调度")
			x.Metadata["execution_boundary"] = workflowExecutionBoundary(workflow)
			payload, txErr = json.Marshal(x)
			if txErr != nil {
				return x, txErr
			}
			result, txErr := tx.ExecContext(r.Context(), `UPDATE experiments SET status=$1,updated_at=$2,payload=$3::jsonb WHERE id=$4 AND workspace_id=$5 AND status IN ('queued','planned')`, x.Status, x.UpdatedAt, string(payload), id, s.cfg.Workspace)
			if txErr != nil {
				return x, txErr
			}
			rows, rowsErr := result.RowsAffected()
			if rowsErr != nil || rows != 1 {
				return x, errors.New("job execution was already claimed")
			}
			confirmedEvent, txErr := insertEventRecordTx(tx, id, "execution_confirmed", "completed", "人工确认已记录", map[string]any{"subject": who.Subject, "role": who.Role, "confirmed_at": confirmedAt})
			if txErr != nil {
				return x, txErr
			}
			plannedEvent, txErr := insertEventRecordTx(tx, id, "execution_planned", "planned", "授权渗透计划已确认，等待本地执行器", map[string]any{"workflow_type": workflow, "execution_boundary": workflowExecutionBoundary(workflow)})
			if txErr != nil {
				return x, txErr
			}
			x = s.ensureOrchestrationState(x, []Event{confirmedEvent, plannedEvent})
			payload, txErr = json.Marshal(x)
			if txErr != nil {
				return x, txErr
			}
			if _, txErr = tx.ExecContext(r.Context(), `UPDATE experiments SET updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4 AND status='planned'`, x.UpdatedAt, string(payload), id, s.cfg.Workspace); txErr != nil {
				return x, txErr
			}
			if txErr = tx.Commit(); txErr != nil {
				return x, txErr
			}
			return x, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
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
		confirmedEvent, txErr := insertEventRecordTx(tx, id, "execution_confirmed", "completed", "人工确认已记录", eventData)
		if txErr != nil {
			cancel()
			return x, txErr
		}
		startedEvent, txErr := insertEventRecordTx(tx, id, "started", "running", "任务执行器已启动", nil)
		if txErr != nil {
			cancel()
			return x, txErr
		}
		x = s.ensureOrchestrationState(x, []Event{confirmedEvent, startedEvent})
		var fencingToken int64
		leaseUntil := time.Now().UTC().Add(30 * time.Second)
		txErr = tx.QueryRowContext(r.Context(), `INSERT INTO worker_leases(experiment_id,workspace_id,owner_id,heartbeat_at,expires_at,fencing_token,version)
			VALUES($1,$2,$3,now(),$4,1,1)
			ON CONFLICT(experiment_id) DO UPDATE SET owner_id=excluded.owner_id,heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at,
				fencing_token=worker_leases.fencing_token+1,version=worker_leases.version+1
			WHERE worker_leases.expires_at <= now()
			RETURNING fencing_token`, id, s.cfg.Workspace, s.workerOwner, leaseUntil).Scan(&fencingToken)
		if txErr != nil {
			cancel()
			if errors.Is(txErr, sql.ErrNoRows) {
				return x, errors.New("job execution lease is held by another worker")
			}
			return x, txErr
		}
		if x.Metadata == nil {
			x.Metadata = map[string]any{}
		}
		x.Metadata["worker_fencing_token"] = fencingToken
		payload, txErr = json.Marshal(x)
		if txErr != nil {
			cancel()
			return x, txErr
		}
		if _, txErr = tx.ExecContext(r.Context(), `UPDATE experiments SET updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4 AND status='running'`, x.UpdatedAt, string(payload), id, s.cfg.Workspace); txErr != nil {
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
		if txErr = tx.Commit(); txErr != nil {
			s.mu.Lock()
			delete(s.running, id)
			s.mu.Unlock()
			cancel()
			return x, txErr
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			s.run(ctx, x)
		}()
		return x, nil
	}

	s.mu.Lock()
	if _, exists := s.running[id]; exists {
		s.mu.Unlock()
		return x, errors.New("job execution was already claimed")
	}
	err = readFileJSON(s.experimentPath(id), &x)
	if err != nil {
		s.mu.Unlock()
		return x, err
	}
	if x.Status != "queued" && x.Status != "planned" {
		s.mu.Unlock()
		return x, errors.New("only queued or planned jobs can run")
	}
	workflow := workflowTypeOf(x)
	if (workflow == "memory_patch" || workflow == "process_injection") && !workflowPlanConfirmed(x) {
		s.mu.Unlock()
		return x, errors.New("动态补丁必须先完成 AI 方案生成、审查和人工确认")
	}
	if workflowExecutionBoundary(workflow) == "plan-only" {
		if x.Metadata == nil {
			x.Metadata = map[string]any{}
		}
		confirmedAt := now()
		x.Metadata["execution_confirmation"] = map[string]any{"actor": who.Subject, "role": who.Role, "timestamp": confirmedAt, "source": who.Source}
		x.Metadata["execution_boundary"] = workflowExecutionBoundary(workflow)
		x = s.status(x, "planned", "已确认授权渗透计划，等待具备执行器后调度")
		if err = writeFileJSON(s.experimentPath(id), x); err != nil {
			s.mu.Unlock()
			return x, err
		}
		s.mu.Unlock()
		s.appendEvent(id, "execution_confirmed", "completed", "人工确认已记录", map[string]any{"subject": who.Subject, "role": who.Role, "confirmed_at": confirmedAt})
		s.appendEvent(id, "execution_planned", "planned", "授权渗透计划已确认，等待本地执行器", map[string]any{"workflow_type": workflow, "execution_boundary": workflowExecutionBoundary(workflow)})
		return x, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	x, eventData = s.confirmedRunningExperiment(x, who)
	if err = writeFileJSON(s.experimentPath(id), x); err != nil {
		s.mu.Unlock()
		cancel()
		return x, err
	}
	s.running[id] = cancel
	s.mu.Unlock()
	s.appendEvent(id, "execution_confirmed", "completed", "人工确认已记录", eventData)
	s.appendEvent(id, "started", "running", "任务执行器已启动", nil)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		s.run(ctx, x)
	}()
	return x, nil
}
func experimentFencingToken(x Experiment) int64 {
	if x.Metadata == nil {
		return 0
	}
	switch value := x.Metadata["worker_fencing_token"].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	default:
		return 0
	}
}

func (s *Server) heartbeatWorkerLease(ctx context.Context, cancel context.CancelFunc, experimentID string, fencingToken int64) {
	if s.db == nil || fencingToken <= 0 {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := s.db.ExecContext(ctx, `UPDATE worker_leases SET heartbeat_at=now(),expires_at=now()+interval '30 seconds',version=version+1
				WHERE experiment_id=$1 AND workspace_id=$2 AND owner_id=$3 AND fencing_token=$4 AND expires_at>now()`, experimentID, s.cfg.Workspace, s.workerOwner, fencingToken)
			if err != nil {
				log.Printf("worker lease heartbeat failed for experiment %s: %v", experimentID, err)
				cancel()
				return
			}
			if rows, _ := result.RowsAffected(); rows != 1 {
				log.Printf("worker lease lost for experiment %s", experimentID)
				cancel()
				return
			}
		}
	}
}

func (s *Server) releaseWorkerLease(experimentID string, fencingToken int64) {
	if s.db == nil || fencingToken <= 0 {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2 AND owner_id=$3 AND fencing_token=$4`, experimentID, s.cfg.Workspace, s.workerOwner, fencingToken)
}

func (s *Server) finalizeWorkerExperiment(x Experiment, eventMessage string, fencingToken int64) error {
	if s.db == nil {
		if _, err := s.mutateExperiment(x.ID, func(current *Experiment) error {
			if current.Status != "running" {
				return errors.New("worker finalization rejected by terminal status")
			}
			*current = x
			return nil
		}); err != nil {
			return err
		}
		s.appendEvent(x.ID, x.Status, x.Status, eventMessage, nil)
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentPayload []byte
	var currentStatus string
	if err = tx.QueryRow(`SELECT status,payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, x.ID, s.cfg.Workspace).Scan(&currentStatus, &currentPayload); err != nil {
		return err
	}
	if currentStatus != "running" {
		return errors.New("worker finalization rejected by terminal status")
	}
	var validLease bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2 AND owner_id=$3 AND fencing_token=$4 AND expires_at>now())`, x.ID, s.cfg.Workspace, s.workerOwner, fencingToken).Scan(&validLease); err != nil {
		return err
	}
	if !validLease {
		return errors.New("worker finalization rejected by fencing token")
	}
	var current Experiment
	if err = json.Unmarshal(currentPayload, &current); err != nil {
		return err
	}
	terminalEvent, err := insertEventRecordTx(tx, x.ID, x.Status, x.Status, eventMessage, nil)
	if err != nil {
		return err
	}
	current.Status = x.Status
	current.UpdatedAt = x.UpdatedAt
	current.Error = x.Error
	current.Artifacts = x.Artifacts
	current.Summary = x.Summary
	current.Metadata = x.Metadata
	current.History = x.History
	current.Reconstruction = x.Reconstruction
	current = s.ensureOrchestrationState(current, []Event{terminalEvent})
	x = current
	payload, err := json.Marshal(x)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE experiments SET status=$1,updated_at=$2,payload=$3::jsonb WHERE id=$4 AND workspace_id=$5 AND status='running'`, x.Status, x.UpdatedAt, string(payload), x.ID, s.cfg.Workspace)
	if err != nil {
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return errors.New("worker finalization lost its state claim")
	}
	if _, err = tx.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2 AND owner_id=$3 AND fencing_token=$4`, x.ID, s.cfg.Workspace, s.workerOwner, fencingToken); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) run(ctx context.Context, x Experiment) {
	fencingToken := experimentFencingToken(x)
	leaseContext, stopHeartbeat := context.WithCancel(ctx)
	defer func() {
		stopHeartbeat()
		s.releaseWorkerLease(x.ID, fencingToken)
		s.mu.Lock()
		delete(s.running, x.ID)
		s.mu.Unlock()
	}()
	if s.db != nil {
		go s.heartbeatWorkerLease(leaseContext, stopHeartbeat, x.ID, fencingToken)
	}
	ctx = leaseContext
	workerEvent := func(kind, status, message string, data map[string]any) bool {
		if eventErr := s.appendWorkerEvent(x.ID, kind, status, message, data, fencingToken); eventErr != nil {
			log.Printf("worker event %s rejected for experiment %s: %v", kind, x.ID, eventErr)
			stopHeartbeat()
			return false
		}
		return true
	}
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
		if s.cfg.RunnerURL == "" && s.cfg.SandboxRuntime != "docker" && s.cfg.SandboxRuntime != "podman" {
			err := errors.New("external model providers require an isolated runner so credentials remain outside the worker")
			latest, loadErr := s.loadExperiment(x.ID)
			if loadErr == nil {
				latest = s.status(latest, "failed", err.Error())
				latest.Error = err.Error()
				if finalizeErr := s.finalizeWorkerExperiment(latest, "分析任务失败", fencingToken); finalizeErr != nil {
					log.Printf("finalize experiment %s failed; terminal event suppressed: %v", x.ID, finalizeErr)
				}
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
				if finalizeErr := s.finalizeWorkerExperiment(latest, "分析任务失败", fencingToken); finalizeErr != nil {
					log.Printf("finalize experiment %s failed; terminal event suppressed: %v", x.ID, finalizeErr)
				}
			}
			return
		}
		brokerContext, cancel := context.WithCancel(ctx)
		brokerCancel = cancel
		go broker.run(brokerContext)
		workerBrokerRoot := brokerRoot
		if s.cfg.RunnerURL != "" || s.cfg.SandboxRuntime == "docker" || s.cfg.SandboxRuntime == "podman" {
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
		if !workerEvent("provider_broker_started", "running", "模型请求代理已启动，分析 worker 保持无网络", map[string]any{"provider": selected.Name, "model": selected.Model, "worker_network": "none", "broker": true}) {
			cancel()
			return
		}
	}
	if brokerCancel != nil {
		defer brokerCancel()
	}
	if fallback && !workerEvent("provider_fallback", "running", "请求的 Provider 不可用，已回退到 "+selected.Name, map[string]any{"requested": requested, "selected": selected.Name}) {
		return
	}
	execution, err := s.startWorkerExecution(ctx, args, processEnv, envNames, workerNetwork)
	if err == nil {
		progressDone := make(chan struct{})
		startedAt := time.Now()
		if !workerEvent("progress", "running", "分析引擎已启动，正在准备输入", map[string]any{"percent": 28, "estimated": true, "elapsed_seconds": 0}) {
			return
		}
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for step := 1; ; step++ {
				select {
				case <-progressDone:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					seconds := int(time.Since(startedAt).Seconds())
					percent := min(88, 28+step*2)
					if !workerEvent("progress", "running", fmt.Sprintf("分析引擎运行中，已用时 %d 秒", seconds), map[string]any{"percent": percent, "estimated": true, "elapsed_seconds": seconds}) {
						return
					}
				}
			}
		}()
		defer execution.Output.Close()
		scanner := bufio.NewScanner(execution.Output)
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
		err = execution.Wait()
		close(progressDone)
		if !workerEvent("result_summary", "running", fmt.Sprintf("执行日志已归档：%d 行，%s", outputLines, byteSize(outputBytes)), map[string]any{"output_lines": outputLines, "log_bytes": outputBytes, "artifact": filepath.ToSlash(filepath.Join("experiments", x.ID, "analysis", "worker-output.json"))}) {
			return
		}
	}
	latest, e := s.loadExperiment(x.ID)
	if e != nil {
		return
	}
	latest.Artifacts = s.collectArtifacts(out)
	latest.Summary = s.artifactSummary(out)
	if ctx.Err() == context.DeadlineExceeded {
		latest = s.status(latest, "failed", "worker timeout")
		latest.Error = "analysis timed out"
	} else if err != nil {
		latest = s.status(latest, "failed", err.Error())
		latest.Error = workerFailureDiagnostics(filepath.Join(out, "worker-output.json"))
		if latest.Error == "" {
			latest.Error = err.Error()
		}
	} else {
		latest = s.status(latest, "completed", "result recorded")
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
		if !workerEvent("project_readiness", "completed", "工程结构与依赖锁定状态已记录", readiness) {
			return
		}
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
		if !workerEvent(eventType, fmt.Sprint(buildState["status"]), "隔离构建结果已记录", buildState) {
			return
		}
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
		if !workerEvent(eventType, fmt.Sprint(behaviorState["status"]), "原程序与重构程序行为对比结果已记录", behaviorState) {
			return
		}
	}
	if repairState, found := loadRepairLoopSummary(out, "build"); found {
		exposeArtifactPaths(repairState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["build_repair_loop"] = repairState
		if !workerEvent("build_repair_recorded", fmt.Sprint(repairState["status"]), "编译修复循环已记录", repairState) {
			return
		}
	}
	if repairState, found := loadRepairLoopSummary(out, "behavior"); found {
		exposeArtifactPaths(repairState, out, s.cfg.Workspace)
		if latest.Metadata == nil {
			latest.Metadata = map[string]any{}
		}
		latest.Metadata["behavior_repair_loop"] = repairState
		if !workerEvent("behavior_repair_recorded", fmt.Sprint(repairState["status"]), "行为修复循环已记录", repairState) {
			return
		}
	}
	providerUsageName := selected.Name
	providerUsageRequests := int64(1)
	providerUsageFailed := err != nil || ctx.Err() == context.DeadlineExceeded
	providerUsageInputTokens := int64(0)
	providerUsageOutputTokens := int64(0)
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
		providerUsageName = fmt.Sprint(modelState["provider"])
		providerUsageRequests = calls
		providerUsageFailed = failed
		providerUsageInputTokens = inputTokens
		providerUsageOutputTokens = outputTokens
		eventType := "model_completed"
		if status != "executed" {
			eventType = "model_" + strings.ReplaceAll(status, "-", "_")
			latest.Reconstruction.BlockingReasons = append(latest.Reconstruction.BlockingReasons, map[string]string{"failed": "model_reconstruction_failed", "dependency-gated": "model_provider_not_ready"}[status])
			latest.Reconstruction.CompleteBuildable = false
		}
		if !workerEvent(eventType, status, "模型重构阶段已记录", modelState) {
			return
		}
	}
	if gateObserved && !latest.Reconstruction.CompleteBuildable && latest.Status == "completed" {
		latest = s.status(latest, "partial", "reconstruction gates remain incomplete")
	}
	eventMessage := map[string]string{"completed": "分析任务已完成", "partial": "分析已结束，完整构建门禁尚未通过", "failed": "分析任务失败", "cancelled": "分析任务已取消"}[latest.Status]
	if eventMessage == "" {
		eventMessage = "分析任务状态已更新"
	}
	if finalizeErr := s.finalizeWorkerExperiment(latest, eventMessage, fencingToken); finalizeErr != nil {
		log.Printf("finalize experiment %s failed; terminal event suppressed: %v", x.ID, finalizeErr)
		return
	}
	s.recordProviderUsage(providerUsageName, providerUsageRequests, providerUsageFailed, providerUsageInputTokens, providerUsageOutputTokens)
}

func workerFailureDiagnostics(path string) string {
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		return ""
	}
	const limit = 16 << 10
	if len(content) > limit {
		content = content[len(content)-limit:]
	}
	return strings.TrimSpace(string(content))
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
	workflow := workflowTypeOf(x)
	params, _ := x.Metadata["workflow_params"].(map[string]any)
	if workflow == "authorized_pentest" {
		objective := strings.TrimSpace(fmt.Sprint(params["objective"]))
		if objective == "" || objective == "<nil>" {
			objective = "authorized assessment"
		}
		args := []string{"-m", "reverse_analyzer", "skills", "route", objective, "--limit", "3"}
		if sample := strings.TrimSpace(x.Sample); sample != "" {
			args = append(args, "--target", sample)
		}
		if endpoint := strings.TrimSpace(fmt.Sprint(params["endpoint"])); endpoint != "" && endpoint != "<nil>" {
			args = append(args, "--endpoint", endpoint)
		}
		return args
	}
	if workflow == "memory_patch" {
		return []string{"-m", "reverse_analyzer", "capability", "run", "--capability", "memory_runtime", "--action", "write", "--pid", fmt.Sprint(params["pid"]), "--out", out, "--param", "address=" + fmt.Sprint(params["address"]), "--param", "data_hex=" + fmt.Sprint(params["data_hex"]), "--param", "expected_hex=" + fmt.Sprint(params["expected_hex"]), "--rollback"}
	}
	if workflow == "process_injection" {
		return []string{"-m", "reverse_analyzer", "capability", "run", "--capability", "injector", "--action", "inject", "--pid", fmt.Sprint(params["pid"]), "--out", out, "--param", "dll_path=" + fmt.Sprint(params["dll_path"]), "--param", "declared_dll_path=" + fmt.Sprint(params["declared_dll_path"]), "--param", "method=" + fmt.Sprint(params["method"]), "--rollback"}
	}
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

func (s *Server) startWorkerExecution(ctx context.Context, pythonArgs, processEnv, envNames []string, network string) (workerExecution, error) {
	if s.cfg.RunnerURL != "" {
		environment := map[string]string{}
		for _, assignment := range processEnv {
			name, value, found := strings.Cut(assignment, "=")
			if found {
				environment[name] = value
			}
		}
		return s.startRunnerJob(ctx, runnerJobRequest{Kind: "analysis", Args: pythonArgs, Env: environment, Network: network})
	}
	if s.cfg.Production {
		return workerExecution{}, errors.New("isolated runner is not configured")
	}
	cmd := s.workerCommandWithNetwork(ctx, pythonArgs, envNames, network)
	cmd.Dir = s.cfg.Workspace
	cmd.Env = append(os.Environ(), processEnv...)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return workerExecution{}, err
	}
	cmd.Stderr = cmd.Stdout
	if err = cmd.Start(); err != nil {
		return workerExecution{}, err
	}
	return workerExecution{Output: output, Wait: cmd.Wait}, nil
}

func (s *Server) startRunnerJob(ctx context.Context, job runnerJobRequest) (workerExecution, error) {
	if s.cfg.RunnerURL == "" || s.cfg.RunnerToken == "" {
		return workerExecution{}, errors.New("isolated runner is not configured")
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return workerExecution{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.RunnerURL+"/v1/jobs/run", bytes.NewReader(payload))
	if err != nil {
		return workerExecution{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Runner-Token", s.cfg.RunnerToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return workerExecution{}, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		message, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return workerExecution{}, fmt.Errorf("runner rejected job: %s", strings.TrimSpace(string(message)))
	}
	return workerExecution{Output: response.Body, Wait: func() error {
		if code := strings.TrimSpace(response.Trailer.Get("X-Runner-Exit-Code")); code != "" && code != "0" {
			message := strings.TrimSpace(response.Trailer.Get("X-Runner-Error"))
			if message == "" {
				message = "runner job exited with code " + code
			}
			return errors.New(message)
		}
		return nil
	}}, nil
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
		cancelledEvent, err := insertEventRecordTx(tx, id, "cancelled", "cancelled", "任务已取消", nil)
		if err != nil {
			return x, err
		}
		x = s.ensureOrchestrationState(x, []Event{cancelledEvent})
		payload, err = json.Marshal(x)
		if err != nil {
			return x, err
		}
		if _, err = tx.Exec(`UPDATE experiments SET updated_at=$1,payload=$2::jsonb WHERE id=$3 AND workspace_id=$4 AND status='cancelled'`, x.UpdatedAt, string(payload), id, s.cfg.Workspace); err != nil {
			return x, err
		}
		if _, err = tx.Exec(`DELETE FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2`, id, s.cfg.Workspace); err != nil {
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
	skillsRoot := strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_SKILLS_DIR"))
	if skillsRoot == "" {
		skillsRoot = filepath.Join(s.cfg.Workspace, "reverse-skills")
	}
	skills := files(skillsRoot, "SKILL.md")
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
	cleanPath := filepath.Clean("/" + r.URL.Path)
	p := filepath.Join(s.cfg.Frontend, cleanPath)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		if t := mime.TypeByExtension(filepath.Ext(p)); t != "" {
			w.Header().Set("Content-Type", t)
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		http.ServeFile(w, r, p)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/") || filepath.Ext(r.URL.Path) != "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
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
			if strings.TrimSpace(x.Name) == "" {
				x.Name = filepath.Base(x.Sample)
			}
			items = append(items, x)
		}
		return items, rows.Err()
	}
	paths, _ := filepath.Glob(filepath.Join(s.cfg.Workspace, "experiments", "*.json"))
	items := []Experiment{}
	for _, p := range paths {
		var x Experiment
		if readFileJSON(p, &x) == nil {
			if strings.TrimSpace(x.Name) == "" {
				x.Name = filepath.Base(x.Sample)
			}
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
	if x.Orchestration != nil {
		x.Orchestration.Flow.Status = status
		x.Orchestration.Flow.UpdatedAt = x.UpdatedAt
		x.Orchestration.Tasks = ensureOrchestrationTasks(x.Orchestration.Tasks, x)
		x.Orchestration.Tasks[0].Status = status
		x.Orchestration.Tasks[0].Result = orchestrationResult(x)
		x.Orchestration.UpdatedAt = x.UpdatedAt
	}
	return x
}

func ensureOrchestrationTasks(tasks []OrchestrationTask, experiment Experiment) []OrchestrationTask {
	if len(tasks) > 0 {
		return tasks
	}
	return newOrchestrationState(experiment).Tasks
}
func (s *Server) appendEvent(id, kind, status, message string, data map[string]any) {
	if s.db != nil && s.dbErr == nil {
		event, err := s.appendDatabaseEvent(id, kind, status, message, data, nil)
		if err != nil {
			log.Printf("append event failed for experiment %s: %v", id, err)
			return
		}
		s.mu.Lock()
		s.eventSeq[id] = event.Sequence
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
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
		b, _ := json.Marshal(event)
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	s.mu.Unlock()
	s.refreshOrchestrationState(id)
}

func (s *Server) appendWorkerEvent(id, kind, status, message string, data map[string]any, fencingToken int64) error {
	if s.db == nil {
		s.appendEvent(id, kind, status, message, data)
		return nil
	}
	event, err := s.appendDatabaseEvent(id, kind, status, message, data, &workerLeaseClaim{ownerID: s.workerOwner, fencingToken: fencingToken})
	if err == nil {
		s.mu.Lock()
		s.eventSeq[id] = event.Sequence
		s.mu.Unlock()
	}
	return err
}

func (s *Server) appendDatabaseEvent(id, kind, status, message string, data map[string]any, claim *workerLeaseClaim) (Event, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback()
	var payload []byte
	var experimentStatus string
	if err = tx.QueryRow(`SELECT status,payload FROM experiments WHERE id=$1 AND workspace_id=$2 FOR UPDATE`, id, s.cfg.Workspace).Scan(&experimentStatus, &payload); err != nil {
		return Event{}, err
	}
	if claim != nil {
		if experimentStatus != "running" {
			return Event{}, errors.New("worker event rejected by terminal status")
		}
		var valid bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_leases WHERE experiment_id=$1 AND workspace_id=$2 AND owner_id=$3 AND fencing_token=$4 AND expires_at>now())`, id, s.cfg.Workspace, claim.ownerID, claim.fencingToken).Scan(&valid); err != nil {
			return Event{}, err
		}
		if !valid {
			return Event{}, errors.New("worker event rejected by fencing token")
		}
	}
	var experiment Experiment
	if err = json.Unmarshal(payload, &experiment); err != nil {
		return Event{}, err
	}
	event, err := insertEventRecordTx(tx, id, kind, status, message, data)
	if err != nil {
		return Event{}, err
	}
	experiment = s.ensureOrchestrationState(experiment, []Event{event})
	payload, err = json.Marshal(experiment)
	if err != nil {
		return Event{}, err
	}
	result, err := tx.Exec(`UPDATE experiments SET status=$1,updated_at=$2,payload=$3::jsonb WHERE id=$4 AND workspace_id=$5`, experiment.Status, experiment.UpdatedAt, string(payload), id, s.cfg.Workspace)
	if err != nil {
		return Event{}, err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return Event{}, errors.New("event orchestration projection was not persisted")
	}
	if err = tx.Commit(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (s *Server) refreshOrchestrationState(id string) {
	experiment, err := s.loadExperiment(id)
	if err != nil {
		return
	}
	events, err := s.events(id)
	if err != nil {
		return
	}
	experiment = s.ensureOrchestrationState(experiment, events)
	if err := s.saveExperiment(experiment); err != nil {
		log.Printf("persist orchestration state failed for experiment %s: %v", id, err)
	}
}

func insertEventTx(tx *sql.Tx, id, kind, status, message string, data map[string]any) (int64, error) {
	event, err := insertEventRecordTx(tx, id, kind, status, message, data)
	return event.Sequence, err
}

func insertEventRecordTx(tx *sql.Tx, id, kind, status, message string, data map[string]any) (Event, error) {
	var sequence int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(sequence),0)+1 FROM flow_events WHERE experiment_id=$1`, id).Scan(&sequence); err != nil {
		return Event{}, err
	}
	event := Event{sequence, now(), kind, status, message, data}
	payload, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if _, err = tx.Exec(`INSERT INTO flow_events(experiment_id,sequence,payload) VALUES($1,$2,$3::jsonb)`, id, sequence, string(payload)); err != nil {
		return Event{}, err
	}
	return event, nil
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
