package main

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type oauthStateRecord struct {
	Hash, Workspace, Redirect string
	ExpiresAt                 time.Time
	ConsumedAt                *time.Time
}

type oauthExchangeRecord struct {
	Hash, Workspace, Subject, Role string
	ExpiresAt                      time.Time
	ConsumedAt                     *time.Time
}

type oauthRegistry struct {
	States    []oauthStateRecord    `json:"states"`
	Exchanges []oauthExchangeRecord `json:"exchanges"`
	Tokens    []tokenRecord         `json:"tokens"`
}

func (s *Server) oauthRegistryPath() string {
	return filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json")
}

func (s *Server) storeOAuthState(state, redirect string, expires time.Time) error {
	if state == "" || redirect == "" || !expires.After(time.Now().Add(-time.Minute)) {
		return errors.New("invalid OAuth state")
	}
	digest := tokenHash(state)
	if s.dbErr != nil {
		return s.dbErr
	}
	if s.db != nil {
		_, err := s.db.Exec(`INSERT INTO oauth_states(state_hash,workspace_id,redirect_uri,expires_at) VALUES($1,$2,$3,$4)`, digest, s.cfg.Workspace, redirect, expires.UTC())
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var registry oauthRegistry
	_ = readFileJSON(s.oauthRegistryPath(), &registry)
	registry.States = append(registry.States, oauthStateRecord{Hash: digest, Workspace: s.cfg.Workspace, Redirect: redirect, ExpiresAt: expires.UTC()})
	if err := os.MkdirAll(filepath.Dir(s.oauthRegistryPath()), 0700); err != nil {
		return err
	}
	return writeFileJSON(s.oauthRegistryPath(), registry)
}

func (s *Server) consumeOAuthState(state, redirect string, current time.Time) error {
	digest := tokenHash(state)
	if s.dbErr != nil {
		return s.dbErr
	}
	if s.db != nil {
		result, err := s.db.Exec(`UPDATE oauth_states SET consumed_at=$1 WHERE state_hash=$2 AND workspace_id=$3 AND redirect_uri=$4 AND consumed_at IS NULL AND expires_at>$1`, current.UTC(), digest, s.cfg.Workspace, redirect)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return errors.New("invalid, expired, or consumed OAuth state")
		}
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var registry oauthRegistry
	if err := readFileJSON(s.oauthRegistryPath(), &registry); err != nil {
		return err
	}
	for index := range registry.States {
		record := &registry.States[index]
		if record.Hash == digest && record.Workspace == s.cfg.Workspace && record.Redirect == redirect && record.ConsumedAt == nil && record.ExpiresAt.After(current) {
			consumed := current.UTC()
			record.ConsumedAt = &consumed
			return writeFileJSON(s.oauthRegistryPath(), registry)
		}
	}
	return errors.New("invalid, expired, or consumed OAuth state")
}

func (s *Server) storeOAuthExchangeCode(code, subject, role string, expires time.Time) error {
	if code == "" || subject == "" || rolePermissions[role] == nil {
		return errors.New("invalid OAuth exchange code")
	}
	digest := tokenHash(code)
	if s.dbErr != nil {
		return s.dbErr
	}
	if s.db != nil {
		_, err := s.db.Exec(`INSERT INTO oauth_exchange_codes(code_hash,workspace_id,subject,role,expires_at) VALUES($1,$2,$3,$4,$5)`, digest, s.cfg.Workspace, subject, role, expires.UTC())
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var registry oauthRegistry
	_ = readFileJSON(s.oauthRegistryPath(), &registry)
	registry.Exchanges = append(registry.Exchanges, oauthExchangeRecord{Hash: digest, Workspace: s.cfg.Workspace, Subject: subject, Role: role, ExpiresAt: expires.UTC()})
	if err := os.MkdirAll(filepath.Dir(s.oauthRegistryPath()), 0700); err != nil {
		return err
	}
	return writeFileJSON(s.oauthRegistryPath(), registry)
}

func (s *Server) consumeOAuthExchangeCode(code string, current time.Time) (string, error) {
	digest := tokenHash(code)
	plainToken, err := issueToken()
	if err != nil {
		return "", err
	}
	if s.dbErr != nil {
		return "", s.dbErr
	}
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			return "", err
		}
		defer tx.Rollback()
		var subject, role string
		if err = tx.QueryRow(`UPDATE oauth_exchange_codes SET consumed_at=$1 WHERE code_hash=$2 AND workspace_id=$3 AND consumed_at IS NULL AND expires_at>$1 RETURNING subject,role`, current.UTC(), digest, s.cfg.Workspace).Scan(&subject, &role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", errors.New("invalid, expired, or consumed OAuth exchange code")
			}
			return "", err
		}
		userID := tokenHash(s.cfg.Workspace + ":" + subject)[:32]
		if _, err = tx.Exec(`INSERT INTO users(id,workspace_id,subject,role) VALUES($1,$2,$3,$4) ON CONFLICT(workspace_id,subject) DO UPDATE SET role=excluded.role`, userID, s.cfg.Workspace, subject, role); err != nil {
			return "", err
		}
		if _, err = tx.Exec(`INSERT INTO api_tokens(id,user_id,token_hash) VALUES($1,$2,$3)`, newID(), userID, tokenHash(plainToken)); err != nil {
			return "", err
		}
		if err = tx.Commit(); err != nil {
			return "", err
		}
		return plainToken, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var registry oauthRegistry
	if err := readFileJSON(s.oauthRegistryPath(), &registry); err != nil {
		return "", err
	}
	var selected *oauthExchangeRecord
	for index := range registry.Exchanges {
		record := &registry.Exchanges[index]
		if record.Hash == digest && record.Workspace == s.cfg.Workspace && record.ConsumedAt == nil && record.ExpiresAt.After(current) {
			selected = record
			break
		}
	}
	if selected == nil {
		return "", errors.New("invalid, expired, or consumed OAuth exchange code")
	}
	consumed := current.UTC()
	selected.ConsumedAt = &consumed
	registry.Tokens = append(registry.Tokens, tokenRecord{ID: newID(), Subject: selected.Subject, Role: selected.Role, Workspace: s.cfg.Workspace, TokenHash: tokenHash(plainToken), CreatedAt: now()})
	if err := os.MkdirAll(filepath.Join(s.cfg.Workspace, ".reverse_analyzer"), 0700); err != nil {
		return "", err
	}
	if err := writeFileJSON(s.oauthRegistryPath(), registry); err != nil {
		return "", err
	}
	return plainToken, nil
}
