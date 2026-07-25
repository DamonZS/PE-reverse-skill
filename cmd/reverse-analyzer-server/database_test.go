package main

import (
	"reflect"
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
	if want := []int64{1, 2, 3, 4, 5, 6, 7, 8}; !reflect.DeepEqual(versions, want) {
		t.Fatalf("migration versions = %v, want %v", versions, want)
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
	if err := validateRuntimeConfig(cfg, "postgres://database/reverse_analyzer"); err != nil {
		t.Fatalf("valid production configuration rejected: %v", err)
	}
}
