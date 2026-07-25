package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type identity struct{ Subject, Role, Workspace, Source string }
type tokenRecord struct {
	ID        string `json:"id,omitempty"`
	Subject   string `json:"subject"`
	Role      string `json:"role"`
	Workspace string `json:"workspace"`
	TokenHash string `json:"token_hash"`
	Revoked   bool   `json:"revoked"`
	CreatedAt string `json:"created_at,omitempty"`
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	_, registryErr := os.Stat(filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json"))
	writeJSON(w, 200, map[string]any{"enabled": s.cfg.Token != "" || registryErr == nil, "legacy_token": s.cfg.Token != "", "token_registry": registryErr == nil, "oauth": map[string]bool{"github": os.Getenv("REVERSE_ANALYZER_GITHUB_CLIENT_ID") != "", "google": os.Getenv("REVERSE_ANALYZER_GOOGLE_CLIENT_ID") != ""}})
}

func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	i := s.authenticate(r)
	if i == nil {
		if s.cfg.Token == "" {
			writeJSON(w, 200, map[string]any{"subject": "local-anonymous", "role": "admin", "workspace": s.cfg.Workspace, "auth_disabled": true})
			return
		}
		writeJSON(w, 401, map[string]any{"error": "authentication required"})
		return
	}
	writeJSON(w, 200, i)
}

func (s *Server) authTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.listAuthTokens(w)
		return
	}
	if r.Method != http.MethodPost {
		method(w)
		return
	}
	var p struct{ Subject, Role, Workspace string }
	if readJSON(r, &p) != nil || p.Subject == "" || rolePermissions[p.Role] == nil {
		bad(w, "subject and valid role are required")
		return
	}
	plainToken, err := issueToken()
	if err != nil {
		respond(w, nil, err)
		return
	}
	// A server process owns one physical workspace root. Request payloads cannot
	// select another tenant; cross-workspace administration uses that tenant's
	// control-plane instance.
	p.Workspace = s.cfg.Workspace
	if s.dbErr != nil {
		respond(w, nil, s.dbErr)
		return
	}
	if s.db != nil {
		tx, err := s.db.Begin()
		if err != nil {
			respond(w, nil, err)
			return
		}
		defer tx.Rollback()
		_, err = tx.Exec(`INSERT INTO workspaces(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, p.Workspace, filepath.Base(p.Workspace))
		userID := tokenHash(p.Workspace + ":" + p.Subject)[:32]
		if err == nil {
			_, err = tx.Exec(`INSERT INTO users(id,workspace_id,subject,role) VALUES($1,$2,$3,$4) ON CONFLICT(workspace_id,subject) DO UPDATE SET role=excluded.role`, userID, p.Workspace, p.Subject, p.Role)
		}
		tokenID := newID()
		if err == nil {
			_, err = tx.Exec(`INSERT INTO api_tokens(id,user_id,token_hash) VALUES($1,$2,$3)`, tokenID, userID, tokenHash(plainToken))
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			respond(w, nil, err)
			return
		}
		writeJSON(w, 201, map[string]any{"id": tokenID, "subject": p.Subject, "role": p.Role, "workspace": p.Workspace, "token": plainToken, "created_at": time.Now().UTC(), "token_stored": "sha256", "backend": "postgresql"})
		return
	}
	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json")
	var f oauthRegistry
	_ = readFileJSON(path, &f)
	record := tokenRecord{ID: newID(), Subject: p.Subject, Role: p.Role, Workspace: p.Workspace, TokenHash: tokenHash(plainToken), CreatedAt: now()}
	f.Tokens = append(f.Tokens, record)
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	if err := writeFileJSON(path, f); err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": record.ID, "subject": p.Subject, "role": p.Role, "workspace": p.Workspace, "token": plainToken, "created_at": record.CreatedAt, "token_stored": "sha256"})
}

func issueToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (s *Server) listAuthTokens(w http.ResponseWriter) {
	if s.dbErr != nil {
		respond(w, nil, s.dbErr)
		return
	}
	if s.db != nil {
		rows, err := s.db.Query(`SELECT t.id,u.subject,u.role,u.workspace_id,t.expires_at,t.revoked_at IS NOT NULL FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE u.workspace_id=$1 ORDER BY t.id`, s.cfg.Workspace)
		if err != nil {
			respond(w, nil, err)
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var id, subject, role, workspace string
			var expires any
			var revoked bool
			if rows.Scan(&id, &subject, &role, &workspace, &expires, &revoked) == nil {
				items = append(items, map[string]any{"id": id, "subject": subject, "role": role, "workspace": workspace, "expires_at": expires, "revoked": revoked})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": items})
		return
	}
	var registry oauthRegistry
	_ = readFileJSON(filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json"), &registry)
	items := []map[string]any{}
	for index, record := range registry.Tokens {
		id := record.ID
		if id == "" {
			id = fmt.Sprintf("legacy-%d", index)
		}
		items = append(items, map[string]any{"id": id, "subject": record.Subject, "role": record.Role, "workspace": record.Workspace, "created_at": record.CreatedAt, "revoked": record.Revoked})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": items})
}

func (s *Server) authTokenItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		method(w)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/tokens/"), "/")
	if id == "" || strings.Contains(id, "/") {
		bad(w, "token id is required")
		return
	}
	if s.dbErr != nil {
		respond(w, nil, s.dbErr)
		return
	}
	if s.db != nil {
		result, err := s.db.Exec(`UPDATE api_tokens SET revoked_at=now() FROM users WHERE api_tokens.id=$1 AND api_tokens.user_id=users.id AND users.workspace_id=$2`, id, s.cfg.Workspace)
		if err != nil {
			respond(w, nil, err)
			return
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "token not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json")
	var registry oauthRegistry
	if readFileJSON(path, &registry) != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "token not found"})
		return
	}
	found := false
	for index := range registry.Tokens {
		if registry.Tokens[index].ID == id {
			registry.Tokens[index].Revoked = true
			found = true
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "token not found"})
		return
	}
	if err := writeFileJSON(path, registry); err != nil {
		respond(w, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type tokenFile struct {
	Tokens []tokenRecord `json:"tokens"`
}

var rolePermissions = map[string]map[string]bool{
	"viewer":  {"workspace.read": true, "artifact.read": true},
	"analyst": {"workspace.read": true, "artifact.read": true, "knowledge.write": true, "analysis.plan": true, "analysis.execute": true},
	"admin":   {"workspace.read": true, "artifact.read": true, "knowledge.write": true, "analysis.plan": true, "analysis.execute": true, "providers.manage": true, "users.manage": true},
}

func tokenHash(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func (s *Server) authenticate(r *http.Request) *identity {
	v := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if v == "" {
		v = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}
	if s.cfg.Token != "" && len(v) == len(s.cfg.Token) && subtle.ConstantTimeCompare([]byte(v), []byte(s.cfg.Token)) == 1 {
		return &identity{"legacy-web-token", "admin", "*", "environment"}
	}
	if s.db != nil && s.dbErr == nil {
		var subject, role, workspace string
		if err := s.db.QueryRow(`SELECT u.subject,u.role,u.workspace_id FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>now())`, tokenHash(v)).Scan(&subject, &role, &workspace); err == nil {
			return &identity{subject, role, workspace, "postgresql"}
		}
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "auth.json"))
	if err != nil {
		return nil
	}
	var f tokenFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	digest := tokenHash(v)
	for _, x := range f.Tokens {
		if !x.Revoked && len(digest) == len(x.TokenHash) && subtle.ConstantTimeCompare([]byte(digest), []byte(x.TokenHash)) == 1 {
			return &identity{x.Subject, x.Role, x.Workspace, "registry"}
		}
	}
	return nil
}
func permission(r *http.Request) string {
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/auth/tokens") {
		return "users.manage"
	}
	if r.Method == "GET" || r.Method == "HEAD" {
		if p == "/api/artifacts" {
			return "artifact.read"
		}
		return "workspace.read"
	}
	if strings.HasPrefix(p, "/api/knowledge") {
		return "knowledge.write"
	}
	if strings.HasPrefix(p, "/api/providers") {
		return "providers.manage"
	}
	if strings.HasSuffix(p, "/execute") || strings.HasSuffix(p, "/cancel") || strings.HasSuffix(p, "/retry") || strings.HasSuffix(p, "/build") || strings.HasSuffix(p, "/patches/apply") || strings.HasSuffix(p, "/patches/rollback") {
		return "analysis.execute"
	}
	return "analysis.plan"
}
func (i *identity) allows(p, workspace string) bool {
	return i != nil && (i.Workspace == "*" || i.Workspace == workspace) && rolePermissions[i.Role][p]
}
