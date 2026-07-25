package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
)

func (s *Server) setAuditTransactionContext(tx *sql.Tx, r *http.Request, who *identity, action string) error {
	if who == nil {
		who = &identity{Subject: "local-anonymous", Role: "admin", Workspace: s.cfg.Workspace, Source: "request"}
	}
	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = newID()
	}
	values := [][2]string{{"actor", who.Subject}, {"role", who.Role}, {"remote_ip", s.clientIP(r)}, {"action", action}, {"outcome", "succeeded"}, {"status_code", "200"}, {"request_id", requestID}}
	for _, value := range values {
		if _, err := tx.Exec(`SELECT set_config($1,$2,true)`, "reverse_analyzer."+value[0], value[1]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) deliverAuditOutbox() error {
	if s.db == nil || s.dbErr != nil {
		return nil
	}
	for {
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			s.setAuditError(err)
			return err
		}
		var id int64
		var workspace, eventID, actor, role, remoteIP, action, resourceType, resourceID, outcome, requestID string
		var status int
		var details []byte
		err = tx.QueryRow(`SELECT id,workspace_id,event_id,actor,role,remote_ip,action,resource_type,resource_id,outcome,status_code,details,request_id FROM audit_outbox WHERE delivered_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(
			&id, &workspace, &eventID, &actor, &role, &remoteIP, &action, &resourceType, &resourceID, &outcome, &status, &details, &requestID,
		)
		if err == sql.ErrNoRows {
			_ = tx.Rollback()
			s.setAuditError(nil)
			return nil
		}
		if err == nil {
			var detailObject map[string]any
			_ = json.Unmarshal(details, &detailObject)
			if detailObject == nil {
				detailObject = map[string]any{}
			}
			detailObject["request_id"] = requestID
			payload, _ := json.Marshal(detailObject)
			_, err = tx.Exec(`INSERT INTO audit_events(event_id,workspace_id,actor,role,remote_ip,action,resource_type,resource_id,outcome,status_code,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb) ON CONFLICT(event_id) DO NOTHING`, eventID, workspace, actor, role, remoteIP, action, resourceType, resourceID, outcome, status, string(payload))
		}
		if err == nil {
			_, err = tx.Exec(`UPDATE audit_outbox SET delivered_at=now() WHERE id=$1 AND delivered_at IS NULL`, id)
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			s.setAuditError(err)
			return err
		}
	}
}
