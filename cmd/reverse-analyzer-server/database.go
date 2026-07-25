package main

import (
	"database/sql"
	"embed"
	_ "embed"
	"fmt"
	_ "github.com/lib/pq"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var databaseMigrations embed.FS

type migration struct {
	Version int64
	Name    string
	SQL     string
}

func migrationPlan() ([]migration, error) {
	entries, err := databaseMigrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	plan := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid migration name %q", entry.Name())
		}
		version, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid migration version in %q", entry.Name())
		}
		body, err := databaseMigrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}
		plan = append(plan, migration{Version: version, Name: entry.Name(), SQL: string(body)})
	}
	sort.Slice(plan, func(i, j int) bool { return plan[i].Version < plan[j].Version })
	for index := range plan {
		if plan[index].Version != int64(index+1) {
			return nil, fmt.Errorf("migration versions must be contiguous from 1, got %d", plan[index].Version)
		}
	}
	return plan, nil
}

func applyMigrations(db *sql.DB) error {
	plan, err := migrationPlan()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock($1)`, int64(0x50455241)); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	for _, item := range plan {
		var applied bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, item.Version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		if _, err = tx.Exec(item.SQL); err != nil {
			return fmt.Errorf("apply migration %s: %w", item.Name, err)
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, item.Version, item.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Server) initDatabase() {
	url := os.Getenv("REVERSE_ANALYZER_DATABASE_URL")
	if url == "" {
		return
	}
	db, err := sql.Open("postgres", url)
	if err == nil {
		err = db.Ping()
	}
	if err == nil {
		err = applyMigrations(db)
	}
	if err == nil {
		_, err = db.Exec(`INSERT INTO workspaces(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, s.cfg.Workspace, filepath.Base(s.cfg.Workspace))
	}
	if err != nil {
		s.dbErr = err
		if db != nil {
			_ = db.Close()
		}
		return
	}
	s.db = db
	s.migrationsOK = true
}
