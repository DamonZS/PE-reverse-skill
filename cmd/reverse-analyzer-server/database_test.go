package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestMigrationPlanIsOrderedAndVersioned(t *testing.T) {
	plan, err := migrationPlan()
	if err != nil {
		t.Fatal(err)
	}
	versions := make([]int64, 0, len(plan))
	for _, migration := range plan {
		versions = append(versions, migration.Version)
		if migration.Name == "" || migration.SQL == "" {
			t.Fatalf("migration must have a name and SQL: %#v", migration)
		}
	}
	if want := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9}; !reflect.DeepEqual(versions, want) {
		t.Fatalf("migration versions = %v, want %v", versions, want)
	}
	workerFencing := plan[len(plan)-1].SQL
	for _, required := range []string{"fencing_token", "version", "worker_leases_active_idx"} {
		if !strings.Contains(workerFencing, required) {
			t.Fatalf("worker fencing migration missing %q", required)
		}
	}
}

func TestProductionConfigurationRequiresPostgreSQLAndAuthentication(t *testing.T) {
	cfg := Config{Production: true}
	if err := validateRuntimeConfig(cfg, ""); err == nil {
		t.Fatal("production must reject a missing PostgreSQL database")
	}
	if err := validateRuntimeConfig(cfg, "postgres://database/reverse_analyzer"); err == nil {
		t.Fatal("production must reject anonymous access")
	}
	cfg.Token = "configured-outside-source"
	if err := validateRuntimeConfig(cfg, "postgres://database/reverse_analyzer"); err == nil {
		t.Fatal("production must require an authenticated isolated runner")
	}
	cfg.RunnerURL = "http://runner:8091"
	cfg.RunnerToken = "configured-runner-token"
	if err := validateRuntimeConfig(cfg, "postgres://database/reverse_analyzer"); err != nil {
		t.Fatalf("valid production configuration rejected: %v", err)
	}
	cfg.SandboxRuntime = "docker"
	if err := validateRuntimeConfig(cfg, "postgres://database/reverse_analyzer"); err == nil {
		t.Fatal("production control plane must not own Docker or Podman")
	}
}
