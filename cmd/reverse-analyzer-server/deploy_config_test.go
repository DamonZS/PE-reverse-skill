package main

import (
	"os"
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
