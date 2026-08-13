package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type config struct {
	Addr, Token, Runtime, Image, Workspace, WorkspaceVolume string
}

type jobRequest struct {
	Kind    string            `json:"kind"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Network string            `json:"network,omitempty"`
	Project string            `json:"project,omitempty"`
	Command string            `json:"command,omitempty"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !runnerAuthorized(cfg.Token, r.Header.Get("X-Runner-Token")) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "runner authentication required"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "runtime": cfg.Runtime, "worker_image": cfg.Image != ""})
	})
	mux.HandleFunc("/v1/jobs/run", func(w http.ResponseWriter, r *http.Request) {
		runJob(cfg, w, r)
	})
	server := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Hour, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("isolated runner listening on %s", cfg.Addr)
	log.Fatal(server.ListenAndServe())
}

func loadConfig() (config, error) {
	cfg := config{
		Addr:            env("REVERSE_ANALYZER_RUNNER_ADDR", "0.0.0.0:8091"),
		Runtime:         env("REVERSE_ANALYZER_RUNNER_RUNTIME", "docker"),
		Image:           strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_WORKER_IMAGE")),
		Workspace:       env("REVERSE_ANALYZER_WORKSPACE", "/workspace"),
		WorkspaceVolume: strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_WORKSPACE_VOLUME")),
	}
	cfg.Token = strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_TOKEN"))
	if tokenFile := strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_RUNNER_TOKEN_FILE")); cfg.Token == "" && tokenFile != "" {
		content, err := os.ReadFile(tokenFile)
		if err != nil {
			return cfg, err
		}
		cfg.Token = strings.TrimSpace(string(content))
	}
	if cfg.Token == "" || cfg.Image == "" {
		return cfg, errors.New("runner token and fixed worker image are required")
	}
	if cfg.Runtime != "docker" && cfg.Runtime != "podman" {
		return cfg, errors.New("runner runtime must be docker or podman")
	}
	if _, err := exec.LookPath(cfg.Runtime); err != nil {
		return cfg, fmt.Errorf("runner runtime unavailable: %w", err)
	}
	if cfg.WorkspaceVolume != "" {
		valid, _ := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, cfg.WorkspaceVolume)
		if !valid {
			return cfg, errors.New("runner workspace volume is invalid")
		}
	}
	return cfg, nil
}

func runnerAuthorized(expected, provided string) bool {
	provided = strings.TrimSpace(provided)
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func runJob(cfg config, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !runnerAuthorized(cfg.Token, r.Header.Get("X-Runner-Token")) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "runner authentication required"})
		return
	}
	var request jobRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 256<<10))
	if decoder.Decode(&request) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid job request"})
		return
	}
	cmd, err := commandForJob(r.Context(), cfg, request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	cmd.Stderr = cmd.Stdout
	if err = cmd.Start(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Trailer", "X-Runner-Exit-Code")
	w.Header().Add("Trailer", "X-Runner-Error")
	w.Header().Add("Trailer", "X-Runner-Output-Truncated")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	copyErr := copyRunnerOutput(w, stdout, 64<<20)
	waitErr := cmd.Wait()
	exitCode := 0
	if waitErr != nil {
		exitCode = 1
		var exitError *exec.ExitError
		if errors.As(waitErr, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	w.Header().Set("X-Runner-Exit-Code", strconv.Itoa(exitCode))
	if errors.Is(copyErr, errRunnerOutputTruncated) {
		w.Header().Set("X-Runner-Output-Truncated", "true")
	}
	if copyErr != nil && !errors.Is(copyErr, errRunnerOutputTruncated) && waitErr == nil {
		waitErr = copyErr
		exitCode = 1
		w.Header().Set("X-Runner-Exit-Code", strconv.Itoa(exitCode))
	}
	if waitErr != nil {
		message := strings.ReplaceAll(waitErr.Error(), "\r", " ")
		message = strings.ReplaceAll(message, "\n", " ")
		if len(message) > 512 {
			message = message[:512]
		}
		w.Header().Set("X-Runner-Error", message)
	}
}

var errRunnerOutputTruncated = errors.New("runner output exceeded response limit")

type cappedRunnerWriter struct {
	writer    io.Writer
	remaining int64
	truncated bool
}

func (w *cappedRunnerWriter) Write(p []byte) (int, error) {
	original := len(p)
	if w.remaining <= 0 {
		w.truncated = true
		return original, nil
	}
	if int64(len(p)) > w.remaining {
		p = p[:w.remaining]
		w.truncated = true
	}
	written, err := w.writer.Write(p)
	w.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	if written != len(p) {
		return written, io.ErrShortWrite
	}
	return original, nil
}

func copyRunnerOutput(dst io.Writer, src io.Reader, limit int64) error {
	capped := &cappedRunnerWriter{writer: dst, remaining: limit}
	_, copyErr := io.Copy(capped, src)
	if copyErr != nil {
		return copyErr
	}
	if capped.truncated {
		return errRunnerOutputTruncated
	}
	return nil
}

func commandForJob(ctx context.Context, cfg config, request jobRequest) (*exec.Cmd, error) {
	if request.Network != "bridge" {
		request.Network = "none"
	}
	mount := fmt.Sprintf("type=bind,src=%s,dst=/workspace", cfg.Workspace)
	if cfg.WorkspaceVolume != "" {
		mount = fmt.Sprintf("type=volume,src=%s,dst=/workspace", cfg.WorkspaceVolume)
	}
	base := []string{"run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--cpus", "1", "--memory", "1024m", "--network", request.Network, "--mount", mount, "--tmpfs", "/tmp:size=256m,mode=1777", "--workdir", "/workspace"}
	for name, value := range request.Env {
		if !allowedEnvironment(name) || len(value) > 4096 {
			return nil, fmt.Errorf("environment variable %q is not allowed", name)
		}
		base = append(base, "--env", name+"="+value)
	}
	switch request.Kind {
	case "analysis":
		if !validAnalysisArgs(request.Args) {
			return nil, errors.New("analysis arguments are not allowed")
		}
		argv := append(base, "--entrypoint", "python", cfg.Image)
		argv = append(argv, request.Args...)
		return exec.CommandContext(ctx, cfg.Runtime, argv...), nil
	case "build":
		project, err := safeRelativeProject(request.Project)
		if err != nil {
			return nil, err
		}
		workdir := filepath.ToSlash(filepath.Join("/workspace", project))
		buildDir := filepath.ToSlash(filepath.Join(workdir, ".build"))
		script := "cmake -S \"$1\" -B \"$2\" && cmake --build \"$2\" --config Release"
		argv := append(base, "--workdir", workdir, "--entrypoint", "/bin/sh", cfg.Image, "-c", script, "runner-build", workdir, buildDir)
		return exec.CommandContext(ctx, cfg.Runtime, argv...), nil
	case "terminal":
		project, err := safeRelativeProject(request.Project)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(request.Command) == "" || len(request.Command) > 16<<10 || strings.ContainsRune(request.Command, '\x00') {
			return nil, errors.New("terminal command is invalid")
		}
		workdir := filepath.ToSlash(filepath.Join("/workspace", project))
		argv := append(base, "--workdir", workdir, "--entrypoint", "/bin/sh", cfg.Image, "-lc", request.Command)
		return exec.CommandContext(ctx, cfg.Runtime, argv...), nil
	default:
		return nil, errors.New("unsupported job kind")
	}
}

func validAnalysisArgs(args []string) bool {
	if len(args) < 3 || args[0] != "-m" {
		return false
	}
	if args[1] != "reverse_analyzer" && args[1] != "reverse_analyzer.archive_reconstruct" {
		return false
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, '\x00') || len(arg) > 8192 {
			return false
		}
	}
	return true
}

func allowedEnvironment(name string) bool {
	return strings.HasPrefix(name, "REVERSE_ANALYZER_") || name == "OPENAI_MODEL"
}

func safeRelativeProject(project string) (string, error) {
	project = filepath.Clean(filepath.FromSlash(strings.TrimSpace(project)))
	if project == "." || filepath.IsAbs(project) || project == ".." || strings.HasPrefix(project, ".."+string(filepath.Separator)) {
		return "", errors.New("project path must remain inside the shared workspace")
	}
	return project, nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
