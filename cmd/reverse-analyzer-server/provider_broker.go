package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const providerBrokerMaxBytes int64 = 4 << 20

var providerBrokerID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type providerBrokerRequest struct {
	SchemaVersion   int             `json:"schema_version"`
	RequestID       string          `json:"request_id"`
	Provider        string          `json:"provider"`
	Model           string          `json:"model"`
	TimeoutSeconds  float64         `json:"timeout_seconds"`
	MaxOutputTokens int             `json:"max_output_tokens"`
	Context         json.RawMessage `json:"context"`
}

type providerBroker struct {
	root, inbox, outbox string
	profile             providerProfile
	client              *http.Client
	mu                  sync.Mutex
	audit               []map[string]any
	seen                map[string]bool
	requestLimit        int
	tokenBudget         int
	reservedTokens      int
	reservedRequests    int
}

func newProviderBroker(root string, profile providerProfile) (*providerBroker, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("provider broker root must be a regular directory")
	}
	b := &providerBroker{root: root, inbox: filepath.Join(root, "inbox"), outbox: filepath.Join(root, "outbox"), profile: profile, client: &http.Client{}, seen: map[string]bool{}, requestLimit: boundedEnvInt("REVERSE_ANALYZER_PROVIDER_REQUEST_LIMIT", 64, 1, 4096), tokenBudget: boundedEnvInt("REVERSE_ANALYZER_PROVIDER_TOKEN_BUDGET", 131072, 1, 1048576)}
	for _, directory := range []string{b.inbox, b.outbox} {
		if err = os.MkdirAll(directory, 0700); err != nil {
			return nil, err
		}
		child, statErr := os.Lstat(directory)
		if statErr != nil || child.Mode()&os.ModeSymlink != 0 || !child.IsDir() {
			return nil, errors.New("provider broker child must be a regular directory")
		}
	}
	return b, nil
}

func (b *providerBroker) run(ctx context.Context) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		b.scan(ctx)
		select {
		case <-ctx.Done():
			b.scan(context.Background())
			return
		case <-ticker.C:
		}
	}
}

func (b *providerBroker) scan(ctx context.Context) {
	entries, err := os.ReadDir(b.inbox)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		b.mu.Lock()
		already := b.seen[id]
		if !already {
			b.seen[id] = true
		}
		b.mu.Unlock()
		if already {
			continue
		}
		b.process(ctx, id, filepath.Join(b.inbox, entry.Name()))
	}
}

func (b *providerBroker) process(parent context.Context, id, path string) {
	started := time.Now()
	requestHash := ""
	response := map[string]any{"schema_version": 1, "request_id": id, "status": "failed"}
	var usage map[string]any
	var model string
	var err error
	info, statErr := os.Lstat(path)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > providerBrokerMaxBytes {
		err = errors.New("broker request is not a bounded regular file")
	} else if !providerBrokerID.MatchString(id) {
		err = errors.New("broker request id is invalid")
	} else {
		raw, readErr := os.ReadFile(path)
		requestHash = sha256Hex(raw)
		if readErr != nil {
			err = readErr
		} else {
			var request providerBrokerRequest
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decodeErr := decoder.Decode(&request); decodeErr != nil {
				err = decodeErr
			} else if request.SchemaVersion != 1 || request.RequestID != id || request.Provider != "openai_compatible" || request.Model != b.profile.Model {
				err = errors.New("broker request identity or selected provider mismatch")
			} else if len(request.Context) == 0 || len(request.Context) > int(providerBrokerMaxBytes) || request.MaxOutputTokens < 1 || request.MaxOutputTokens > 131072 || request.TimeoutSeconds < 1 || request.TimeoutSeconds > 600 {
				err = errors.New("broker request bounds are invalid")
			} else if !b.reserve(request.MaxOutputTokens) {
				err = errors.New("broker task request or output-token budget exhausted")
			} else {
				model = request.Model
				var result map[string]any
				result, usage, err = b.invoke(parent, request)
				if err == nil {
					response["status"] = "ok"
					response["result"] = result
				}
			}
		}
	}
	if err != nil {
		response["error"] = fmt.Sprintf("provider broker: %s", err)
	}
	encoded, _ := json.Marshal(response)
	responseHash := sha256Hex(encoded)
	_ = atomicBrokerWrite(filepath.Join(b.outbox, id+".json"), encoded)
	b.mu.Lock()
	b.audit = append(b.audit, map[string]any{"request_id": id, "request_sha256": requestHash, "response_sha256": responseHash, "provider": b.profile.Name, "model": model, "status": response["status"], "usage": usage, "duration_ms": time.Since(started).Milliseconds()})
	audit := append([]map[string]any(nil), b.audit...)
	b.mu.Unlock()
	auditPayload, _ := json.MarshalIndent(map[string]any{"schema_version": 1, "worker_network": "none", "broker": true, "requests": audit}, "", "  ")
	_ = atomicBrokerWrite(filepath.Join(b.root, "audit.json"), append(auditPayload, '\n'))
}

func (b *providerBroker) reserve(maxOutputTokens int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reservedRequests >= b.requestLimit || b.reservedTokens+maxOutputTokens > b.tokenBudget {
		return false
	}
	b.reservedRequests++
	b.reservedTokens += maxOutputTokens
	return true
}

func boundedEnvInt(name string, fallback, minimum, maximum int) int {
	value := fallback
	if parsed, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		value = parsed
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func reconstructionContract(raw json.RawMessage) (string, []string, []string, string) {
	var root any
	if json.Unmarshal(raw, &root) != nil {
		return "", nil, nil, ""
	}
	phase := ""
	var find func(any) map[string]any
	find = func(value any) map[string]any {
		switch current := value.(type) {
		case map[string]any:
			if phase == "" {
				phase, _ = current["phase"].(string)
			}
			if contract, ok := current["strict_output_contract"].(map[string]any); ok {
				return contract
			}
			for _, child := range current {
				if found := find(child); found != nil {
					return found
				}
			}
		case []any:
			for _, child := range current {
				if found := find(child); found != nil {
					return found
				}
			}
		}
		return nil
	}
	contract := find(root)
	if contract == nil {
		return "", nil, nil, phase
	}
	strings := func(value any) []string {
		items, _ := value.([]any)
		result := make([]string, 0, len(items))
		seen := map[string]bool{}
		for _, item := range items {
			text, ok := item.(string)
			if ok && text != "" && !seen[text] {
				seen[text] = true
				result = append(result, text)
			}
		}
		return result
	}
	paths := strings(contract["allowed_source_paths"])
	evidence := append(append([]string(nil), paths...), strings(contract["allowed_graph_evidence"])...)
	moduleID, _ := contract["module_id"].(string)
	return moduleID, paths, evidence, phase
}

func (b *providerBroker) invoke(parent context.Context, request providerBrokerRequest) (map[string]any, map[string]any, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(request.TimeoutSeconds*float64(time.Second)))
	defer cancel()
	moduleID, allowedPaths, allowedEvidence, phase := reconstructionContract(request.Context)
	idSchema := map[string]any{"type": "string"}
	pathSchema := map[string]any{"type": "string"}
	evidenceItemSchema := map[string]any{"type": "string"}
	if moduleID != "" {
		idSchema["const"] = moduleID
	}
	if len(allowedPaths) > 0 {
		pathSchema["enum"] = allowedPaths
	}
	if len(allowedEvidence) > 0 {
		evidenceItemSchema["enum"] = allowedEvidence
	}
	stringArray := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	responseSchema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"modules", "dependency_edges", "source_changes"},
		"properties": map[string]any{
			"modules": map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": map[string]any{
				"type": "object", "additionalProperties": false,
				"required":   []string{"id", "responsibility", "interfaces", "missing_implementations", "evidence"},
				"properties": map[string]any{"id": idSchema, "responsibility": map[string]any{"type": "string", "minLength": 1}, "interfaces": stringArray, "missing_implementations": stringArray, "evidence": stringArray},
			}},
			"dependency_edges": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"source", "target", "reason"},
				"properties": map[string]any{"source": map[string]any{"type": "string"}, "target": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"}},
			}},
			"source_changes": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"path", "content", "reason", "evidence"},
				"properties": map[string]any{"path": pathSchema, "content": map[string]any{"type": "string", "minLength": 1}, "reason": map[string]any{"type": "string", "minLength": 1}, "evidence": map[string]any{"type": "array", "minItems": 1, "items": evidenceItemSchema}},
			}},
		},
	}
	systemInstruction := "You are an authorized defensive reverse-analysis source-reconstruction assistant. Return only the business JSON object requested by the user context and its strict_output_contract. The top-level keys must be modules, dependency_edges, and source_changes. modules MUST contain exactly one complete object with id, responsibility, interfaces, missing_implementations, and evidence. source_changes MUST contain at least one complete compilable file. Every source_changes.path value MUST equal one allowed_source_paths value byte-for-byte; never add words such as existing, prefixes, explanations, or absolute directories. Every source_changes.evidence MUST include that exact allowed source path. Never return empty modules or source_changes. Never return an OpenAI envelope. Cite only evidence present in the context."
	if phase == "behavior_repair" {
		systemInstruction = "You are repairing a compiled program after a real behavior comparison failed. Implement every field of repair_recipe literally using the target language standard I/O APIs: write exact stdout_text and stderr_text, create every output path with evidence-derived content matching its size/hash, then return the exact exit_code. Rewrite the complete allowed source file; changing only comments or copying the current main body is invalid. Return only the strict business JSON object; source_changes.path and evidence must use the allowed path byte-for-byte."
	}
	payload := map[string]any{
		"model":           request.Model,
		"max_tokens":      request.MaxOutputTokens,
		"temperature":     0,
		"response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "module_reconstruction", "strict": true, "schema": responseSchema}},
		"messages": []map[string]any{
			{"role": "system", "content": systemInstruction},
			{"role": "user", "content": string(request.Context)},
		},
	}
	body, _ := json.Marshal(payload)
	keys := providerAPIKeys(b.profile)
	if len(keys) == 0 {
		return nil, nil, errors.New("provider has no configured credential slots")
	}
	var httpResponse *http.Response
	selectedSlot := 0
	failures := []map[string]any{}
	for slot, key := range keys {
		httpRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, stringsTrimRightSlash(b.profile.BaseURL)+"/chat/completions", bytes.NewReader(body))
		if requestErr != nil {
			return nil, nil, requestErr
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Authorization", "Bearer "+key)
		candidate, callErr := b.client.Do(httpRequest)
		if callErr != nil {
			failures = append(failures, map[string]any{"key_slot": slot + 1, "error_type": fmt.Sprintf("%T", callErr)})
			if slot+1 < len(keys) {
				continue
			}
			return nil, nil, fmt.Errorf("provider credential slots exhausted: %w", callErr)
		}
		if candidate.StatusCode >= 200 && candidate.StatusCode < 300 {
			httpResponse, selectedSlot = candidate, slot+1
			break
		}
		status := candidate.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(candidate.Body, 64<<10))
		candidate.Body.Close()
		failures = append(failures, map[string]any{"key_slot": slot + 1, "http_status": status, "error_type": "http_status"})
		if status != 401 && status != 403 && status != 429 && status < 500 {
			return nil, nil, fmt.Errorf("provider returned HTTP %d", status)
		}
		if slot+1 == len(keys) {
			return nil, nil, fmt.Errorf("provider returned HTTP %d after all credential slots", status)
		}
	}
	if httpResponse == nil {
		return nil, nil, errors.New("provider credential slots exhausted")
	}
	defer httpResponse.Body.Close()
	limited := io.LimitReader(httpResponse.Body, providerBrokerMaxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || int64(len(raw)) > providerBrokerMaxBytes {
		return nil, nil, errors.New("provider response exceeded broker limit")
	}
	var decoded struct {
		ID      string         `json:"id"`
		Model   string         `json:"model"`
		Usage   map[string]any `json:"usage"`
		Choices []struct {
			Message      map[string]any `json:"message"`
			FinishReason any            `json:"finish_reason"`
		} `json:"choices"`
	}
	if err = json.Unmarshal(raw, &decoded); err != nil || len(decoded.Choices) == 0 {
		return nil, nil, errors.New("provider response did not contain a valid choice")
	}
	content := fmt.Sprint(decoded.Choices[0].Message["content"])
	usage := decoded.Usage
	if usage == nil {
		usage = map[string]any{}
	}
	usage["key_slot"] = selectedSlot
	usage["fallback_count"] = selectedSlot - 1
	usage["key_failures"] = failures
	result := map[string]any{"content": content, "final_answer": content, "confidence": 0.7, "metadata": map[string]any{"model": decoded.Model, "usage": usage, "finish_reason": decoded.Choices[0].FinishReason, "request_id": decoded.ID, "broker": true, "worker_network": "none", "key_slot": selectedSlot, "fallback_count": selectedSlot - 1}}
	return result, usage, nil
}

func atomicBrokerWrite(path string, content []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func stringsTrimRightSlash(value string) string {
	for len(value) > 0 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	return value
}
