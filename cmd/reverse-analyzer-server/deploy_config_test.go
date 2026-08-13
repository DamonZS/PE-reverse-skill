package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionDeploymentHasDurableHealthyNonRootServices(t *testing.T) {
	root := filepath.Join("..", "..")
	compose, err := os.ReadFile(filepath.Join(root, "deploy", "compose.production.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	for _, required := range []string{"healthcheck:", "condition: service_healthy", "reverse_analyzer_postgres:", "reverse_analyzer_workspace:", "read_only: true", "user: \"10001:10001\"", "stop_grace_period:", "secrets:", "POSTGRES_PASSWORD_FILE", "REVERSE_ANALYZER_WEB_TOKEN_FILE", "REVERSE_ANALYZER_GITHUB_CLIENT_SECRET_FILE"} {
		if !strings.Contains(text, required) {
			t.Fatalf("production compose missing %q", required)
		}
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil || !strings.Contains(string(dockerfile), "USER reverse-analyzer") || !strings.Contains(string(dockerfile), "postgresql-client") || !strings.Contains(string(dockerfile), "platform-entrypoint") {
		t.Fatalf("runtime image must use a non-root user: %v", err)
	}
	environment, err := os.ReadFile(filepath.Join(root, "deploy", ".env.production.example"))
	if err != nil || strings.Contains(string(environment), "change-me") || strings.Contains(string(environment), "POSTGRES_PASSWORD=") || strings.Contains(string(environment), "WEB_TOKEN=") {
		t.Fatalf("production environment template is missing or contains an unsafe default: %v", err)
	}
}

func TestProductionDockerSocketIsIsolatedToRunner(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range []string{"compose.production.yml", "compose.aliyun.yml"} {
		content, err := os.ReadFile(filepath.Join(root, "deploy", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		webStart := strings.Index(text, "  web:")
		runnerStart := strings.Index(text, "  runner:")
		if webStart < 0 || runnerStart < 0 || runnerStart <= webStart {
			t.Fatalf("%s must define web before an isolated runner", name)
		}
		webSection := text[webStart:runnerStart]
		runnerSection := text[runnerStart:]
		for _, forbidden := range []string{"/var/run/docker.sock", "DOCKER_GID", "REVERSE_ANALYZER_SANDBOX_RUNTIME"} {
			if strings.Contains(webSection, forbidden) {
				t.Fatalf("%s web service must not contain %q", name, forbidden)
			}
		}
		for _, required := range []string{"REVERSE_ANALYZER_RUNNER_URL", "REVERSE_ANALYZER_RUNNER_TOKEN_FILE"} {
			if !strings.Contains(webSection, required) {
				t.Fatalf("%s web service missing %q", name, required)
			}
		}
		for _, required := range []string{"/var/run/docker.sock", "REVERSE_ANALYZER_RUNNER_WORKER_IMAGE", "REVERSE_ANALYZER_RUNNER_RUNTIME", "runner_token"} {
			if !strings.Contains(runnerSection, required) {
				t.Fatalf("%s runner service missing %q", name, required)
			}
		}
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dockerfile), " docker.io ") {
		t.Fatal("web image must not install Docker CLI")
	}
	if !strings.Contains(string(dockerfile), "COPY reverse-skills ./reverse-skills") {
		t.Fatal("production worker image must include reverse-skills")
	}
	for _, name := range []string{"compose.production.yml", "compose.aliyun.yml"} {
		content, err := os.ReadFile(filepath.Join(root, "deploy", name))
		if err != nil || !strings.Contains(string(content), "X-Runner-Token") || !strings.Contains(string(content), "runner_token") {
			t.Fatalf("%s runner healthcheck must authenticate with runner_token: %v", name, err)
		}
	}
	if _, err = os.Stat(filepath.Join(root, "Dockerfile.runner")); err != nil {
		t.Fatal("runner image is missing")
	}
}

func TestRoutingSkillFilesExistAndAreTracked(t *testing.T) {
	root := filepath.Join("..", "..")
	skillRoot := filepath.Join(root, "reverse-skills", "skills")
	content, err := os.ReadFile(filepath.Join(skillRoot, "config", "routing.json"))
	if err != nil {
		t.Fatal(err)
	}
	var routing struct {
		MasterSkill struct {
			Path string `json:"path"`
		} `json:"master_skill"`
		Routes []struct {
			SkillID string `json:"skill_id"`
		} `json:"routes"`
	}
	if err = json.Unmarshal(content, &routing); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join("reverse-skills", "skills", routing.MasterSkill.Path)}
	for _, route := range routing.Routes {
		paths = append(paths, filepath.Join("reverse-skills", "skills", filepath.FromSlash(route.SkillID), "SKILL.md"))
	}
	for _, path := range paths {
		if _, err = os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("routing skill is missing: %s: %v", filepath.ToSlash(path), err)
		}
		command := exec.Command("git", "ls-files", "--error-unmatch", "--", filepath.ToSlash(path))
		command.Dir = root
		if output, commandErr := command.CombinedOutput(); commandErr != nil {
			t.Fatalf("routing skill is not tracked: %s: %s", filepath.ToSlash(path), strings.TrimSpace(string(output)))
		}
	}
}

func TestP10AcceptanceScriptProducesEvidenceAndAlwaysCleansUp(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "scripts", "accept_p10.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{"finally", "p10-acceptance.json", "TestPostgreSQL", "/readyz", "reverse-analyzer-backup", "RESTORE_PLATFORM_BACKUP", "ConvertTo-Json", "docker rm -f", "git-tree+binary-diff+all-untracked-sha256-v2", "workspace content changed during acceptance", "exclusions = $exclusions", "included untracked content did not change workspace digest", "restore_transaction_fault_rollback"} {
		if !strings.Contains(text, required) {
			t.Fatalf("P10 acceptance script missing %q", required)
		}
	}
}
