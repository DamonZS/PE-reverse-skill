package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type auditRecordDescriptor struct {
	Action, ResourceType, ResourceID string
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *auditResponseWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(value)
}

func (w *auditResponseWriter) flush() {
	w.ResponseWriter.WriteHeader(w.status)
	_, _ = w.ResponseWriter.Write(w.body.Bytes())
}

func auditDescriptor(r *http.Request) (auditRecordDescriptor, bool) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	descriptor := auditRecordDescriptor{ResourceID: path}
	if len(parts) >= 2 && parts[0] == "api" && parts[1] == "experiments" {
		descriptor.ResourceType = "experiment"
		if len(parts) >= 3 {
			descriptor.ResourceID = parts[2]
		}
		if len(parts) == 2 && r.Method == http.MethodPost {
			descriptor.Action = "experiment.create"
		} else if len(parts) >= 4 {
			switch parts[3] {
			case "execute", "cancel", "retry":
				descriptor.Action = "experiment." + parts[3]
			case "build":
				descriptor.Action = "source.build"
			case "source":
				if r.Method == http.MethodPut {
					descriptor.Action = "source.save"
				}
			case "patches":
				if len(parts) >= 5 && (parts[4] == "apply" || parts[4] == "rollback" || parts[4] == "plan" || parts[4] == "ai-plan" || parts[4] == "ai-apply" || parts[4] == "ai-rollback") {
					descriptor.Action = "patch." + strings.TrimPrefix(parts[4], "ai-")
				}
			case "runtime-marks":
				descriptor.Action = "runtime-mark.create"
			case "terminal":
				if len(parts) == 4 && r.Method == http.MethodPost {
					descriptor.Action = "terminal.execute"
					descriptor.ResourceType = "terminal"
				} else if len(parts) == 6 && parts[5] == "stop" && r.Method == http.MethodPost {
					descriptor.Action = "terminal.cancel"
					descriptor.ResourceType = "terminal"
					descriptor.ResourceID = parts[4]
				}
			case "tool-calls":
				if len(parts) == 6 && r.Method == http.MethodPost && (parts[5] == "retry" || parts[5] == "cancel") {
					descriptor.Action = "tool." + parts[5]
					descriptor.ResourceType = "tool_call"
					descriptor.ResourceID = parts[4]
				}
			}
		}
	} else if path == "api/providers" && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		descriptor = auditRecordDescriptor{"provider.update", "provider", "configuration"}
	} else if path == "api/providers/test" && r.Method == http.MethodPost {
		descriptor = auditRecordDescriptor{"provider.test", "provider", "connection"}
	} else if path == "api/knowledge" && r.Method == http.MethodPost {
		descriptor = auditRecordDescriptor{"knowledge.create", "knowledge", "new"}
	} else if len(parts) == 3 && parts[0] == "api" && parts[1] == "knowledge" && (r.Method == http.MethodPatch || r.Method == http.MethodDelete) {
		action := "knowledge.update"
		if r.Method == http.MethodDelete {
			action = "knowledge.delete"
		}
		descriptor = auditRecordDescriptor{action, "knowledge", parts[2]}
	} else if path == "api/auth/tokens" && r.Method == http.MethodPost {
		descriptor = auditRecordDescriptor{"token.create", "api_token", "new"}
	} else if len(parts) == 4 && strings.Join(parts[:3], "/") == "api/auth/tokens" && r.Method == http.MethodDelete {
		descriptor = auditRecordDescriptor{"token.revoke", "api_token", parts[3]}
	} else if path == "api/uploads" && r.Method == http.MethodPost {
		descriptor = auditRecordDescriptor{"upload.create", "upload", "new"}
	} else if path == "api/auth/oauth/exchange" && r.Method == http.MethodPost {
		descriptor = auditRecordDescriptor{"oauth.exchange", "oauth", "exchange-code"}
	}
	return descriptor, descriptor.Action != ""
}

func (s *Server) auditAction(r *http.Request, who *identity, descriptor auditRecordDescriptor, outcome string, status int, details map[string]any) error {
	if who == nil {
		who = &identity{Subject: "anonymous", Role: "anonymous", Workspace: s.cfg.Workspace, Source: "request"}
	}
	entry := map[string]any{"timestamp": now(), "actor": who.Subject, "role": who.Role, "workspace": s.cfg.Workspace, "remote_ip": s.clientIP(r), "action": descriptor.Action, "resource_type": descriptor.ResourceType, "resource_id": descriptor.ResourceID, "outcome": outcome, "status_code": status, "details": details}
	if s.dbErr != nil {
		return s.dbErr
	}
	if s.db != nil {
		payload, _ := json.Marshal(details)
		_, err := s.db.Exec(`INSERT INTO audit_events(workspace_id,actor,role,remote_ip,action,resource_type,resource_id,outcome,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, s.cfg.Workspace, who.Subject, who.Role, s.clientIP(r), descriptor.Action, descriptor.ResourceType, descriptor.ResourceID, outcome, string(payload))
		s.setAuditError(err)
		return err
	}
	entryPath := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(entryPath), 0700); err != nil {
		s.setAuditError(err)
		return err
	}
	payload, _ := json.Marshal(entry)
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(entryPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		_, err = file.Write(append(payload, '\n'))
		err = errors.Join(err, file.Close())
	}
	s.auditErr = err
	return err
}

func (s *Server) setAuditError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditErr = err
}

func (s *Server) auditError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auditErr
}
