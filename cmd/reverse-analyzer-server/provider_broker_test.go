package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProviderBrokerInvokesSelectedProviderAndWritesSecretFreeAudit(t *testing.T) {
	var calls atomic.Int32
	var received map[string]any
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer broker-test-secret" {
			t.Fatalf("authorization was not supplied to provider: %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode provider request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "response-1", "model": "test-model", "choices": []any{map[string]any{"message": map[string]any{"content": "real inference"}, "finish_reason": "stop"}}, "usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}})
	}))
	defer provider.Close()
	t.Setenv("BROKER_TEST_KEY", "broker-test-secret")
	root := t.TempDir()
	broker, err := newProviderBroker(root, providerProfile{Name: "openai_compatible", Kind: "openai-compatible", Model: "test-model", BaseURL: provider.URL + "/v1", APIKeyEnv: "BROKER_TEST_KEY", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	writeBrokerRequest(t, broker.inbox, id, map[string]any{"schema_version": 1, "request_id": id, "provider": "openai_compatible", "model": "test-model", "timeout_seconds": 5, "max_output_tokens": 32, "context": map[string]any{"context": map[string]any{"phase": "behavior_repair", "strict_output_contract": map[string]any{"module_id": "program", "allowed_source_paths": []string{"targets/program/main.c"}, "allowed_graph_evidence": []string{"node-1"}}}}})
	broker.process(context.Background(), id, filepath.Join(broker.inbox, id+".json"))
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d", calls.Load())
	}
	format, _ := received["response_format"].(map[string]any)
	jsonSchema, _ := format["json_schema"].(map[string]any)
	schema, _ := jsonSchema["schema"].(map[string]any)
	properties, _ := schema["properties"].(map[string]any)
	modules, _ := properties["modules"].(map[string]any)
	sourceChanges, _ := properties["source_changes"].(map[string]any)
	if format["type"] != "json_schema" || jsonSchema["strict"] != true || modules["minItems"] != float64(1) || modules["maxItems"] != float64(1) || sourceChanges["minItems"] != float64(1) {
		t.Fatalf("provider request did not enforce strict reconstruction schema: %#v", format)
	}
	moduleItems, _ := modules["items"].(map[string]any)
	moduleProperties, _ := moduleItems["properties"].(map[string]any)
	idProperty, _ := moduleProperties["id"].(map[string]any)
	changeItems, _ := sourceChanges["items"].(map[string]any)
	changeProperties, _ := changeItems["properties"].(map[string]any)
	pathProperty, _ := changeProperties["path"].(map[string]any)
	if idProperty["const"] != "program" || len(pathProperty["enum"].([]any)) != 1 || pathProperty["enum"].([]any)[0] != "targets/program/main.c" {
		t.Fatalf("provider schema did not bind module and source path contract: %#v %#v", idProperty, pathProperty)
	}
	messages, _ := received["messages"].([]any)
	system, _ := messages[0].(map[string]any)
	if !strings.Contains(system["content"].(string), "behavior comparison failed") {
		t.Fatalf("behavior repair did not receive specialized system instruction: %#v", system)
	}
	var response map[string]any
	if err = readFileJSON(filepath.Join(broker.outbox, id+".json"), &response); err != nil {
		t.Fatal(err)
	}
	if response["status"] != "ok" {
		t.Fatalf("unexpected broker response: %#v", response)
	}
	audit, err := os.ReadFile(filepath.Join(root, "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(audit)
	for _, required := range []string{`"worker_network": "none"`, `"broker": true`, `"request_sha256"`, `"response_sha256"`, `"total_tokens": 7`} {
		if !strings.Contains(text, required) {
			t.Fatalf("audit missing %s: %s", required, text)
		}
	}
	if strings.Contains(text, "broker-test-secret") {
		t.Fatal("broker audit leaked provider secret")
	}
}

func TestProviderBrokerUsesNativeResponsesProtocol(t *testing.T) {
	var received map[string]any
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("responses path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "response-native", "model": "gpt-test", "output_text": "native inference",
			"usage": map[string]any{"input_tokens": 5, "output_tokens": 2, "total_tokens": 7},
		})
	}))
	defer provider.Close()
	t.Setenv("RESPONSES_TEST_KEY", "responses-test-secret")
	root := t.TempDir()
	broker, err := newProviderBroker(root, providerProfile{Name: "openai_compatible", Kind: "openai-compatible", Protocol: "responses", Model: "gpt-test", BaseURL: provider.URL + "/v1", APIKeyEnv: "RESPONSES_TEST_KEY", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("e", 32)
	writeBrokerRequest(t, broker.inbox, id, map[string]any{"schema_version": 1, "request_id": id, "provider": "openai_compatible", "model": "gpt-test", "timeout_seconds": 5, "max_output_tokens": 32, "context": map[string]any{"context": map[string]any{"strict_output_contract": map[string]any{"module_id": "program", "allowed_source_paths": []string{"targets/program/main.c"}}}}})
	broker.process(context.Background(), id, filepath.Join(broker.inbox, id+".json"))
	if received["instructions"] == nil || received["input"] == nil || received["messages"] != nil || received["max_output_tokens"] != float64(32) {
		t.Fatalf("invalid Responses payload: %#v", received)
	}
	text, _ := received["text"].(map[string]any)
	format, _ := text["format"].(map[string]any)
	if format["type"] != "json_schema" || format["strict"] != true {
		t.Fatalf("missing strict Responses schema: %#v", format)
	}
	var response map[string]any
	if err := readFileJSON(filepath.Join(broker.outbox, id+".json"), &response); err != nil || response["status"] != "ok" {
		t.Fatalf("unexpected broker response: %#v err=%v", response, err)
	}
}

func TestProviderBrokerFallsBackAcrossCredentialSlots(t *testing.T) {
	const first = "first-broker-secret"
	const second = "second-broker-secret"
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer "+first {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+second {
			t.Errorf("unexpected credential slot")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"fallback-request","model":"test-model","usage":{"input_tokens":1,"output_tokens":1},"choices":[{"message":{"content":"{\"modules\":[{\"id\":\"program\",\"responsibility\":\"r\",\"interfaces\":[],\"missing_implementations\":[],\"evidence\":[]}],\"dependency_edges\":[],\"source_changes\":[{\"path\":\"targets/program/main.c\",\"content\":\"int main(void){return 0;}\",\"reason\":\"r\",\"evidence\":[\"targets/program/main.c\"]}]}"},"finish_reason":"stop"}]}`)
	}))
	defer provider.Close()
	t.Setenv("BROKER_FALLBACK_KEYS", "")
	t.Setenv("OPENAI_API_KEYS", first+","+second)
	root := t.TempDir()
	broker, err := newProviderBroker(root, providerProfile{Name: "openai_compatible", Kind: "openai-compatible", Model: "test-model", BaseURL: provider.URL + "/v1", APIKeyEnv: "BROKER_FALLBACK_KEYS", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 32)
	writeBrokerRequest(t, broker.inbox, id, map[string]any{"schema_version": 1, "request_id": id, "provider": "openai_compatible", "model": "test-model", "timeout_seconds": 5, "max_output_tokens": 32, "context": map[string]any{"context": map[string]any{"strict_output_contract": map[string]any{"module_id": "program", "allowed_source_paths": []string{"targets/program/main.c"}}}}})
	broker.scan(context.Background())
	if calls.Load() != 2 {
		t.Fatalf("provider calls = %d", calls.Load())
	}
	raw, err := os.ReadFile(filepath.Join(root, "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(first)) || bytes.Contains(raw, []byte(second)) {
		t.Fatal("broker audit leaked a credential")
	}
	var audit struct {
		Requests []struct {
			Usage map[string]any `json:"usage"`
		} `json:"requests"`
	}
	if json.Unmarshal(raw, &audit) != nil || len(audit.Requests) != 1 {
		t.Fatal("invalid broker audit")
	}
	if audit.Requests[0].Usage["key_slot"] != float64(2) || audit.Requests[0].Usage["fallback_count"] != float64(1) {
		t.Fatalf("fallback metadata = %#v", audit.Requests[0].Usage)
	}
}

func TestProviderBrokerRejectsUnknownFieldsIdentityMismatchAndOversizeWithoutHTTP(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer provider.Close()
	broker, err := newProviderBroker(t.TempDir(), providerProfile{Name: "openai_compatible", Kind: "openai-compatible", Model: "selected", BaseURL: provider.URL, APIKeyEnv: "MISSING"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id      string
		payload map[string]any
	}{
		{strings.Repeat("b", 32), map[string]any{"schema_version": 1, "request_id": strings.Repeat("b", 32), "provider": "openai_compatible", "model": "selected", "timeout_seconds": 5, "max_output_tokens": 32, "context": map[string]any{}, "base_url": "https://attacker.invalid"}},
		{strings.Repeat("c", 32), map[string]any{"schema_version": 1, "request_id": strings.Repeat("c", 32), "provider": "openai_compatible", "model": "other", "timeout_seconds": 5, "max_output_tokens": 32, "context": map[string]any{}}},
	}
	for _, item := range cases {
		writeBrokerRequest(t, broker.inbox, item.id, item.payload)
		broker.process(context.Background(), item.id, filepath.Join(broker.inbox, item.id+".json"))
		var response map[string]any
		if err = readFileJSON(filepath.Join(broker.outbox, item.id+".json"), &response); err != nil || response["status"] != "failed" {
			t.Fatalf("request should fail: %#v %v", response, err)
		}
	}
	oversizedID := strings.Repeat("d", 32)
	oversizedPath := filepath.Join(broker.inbox, oversizedID+".json")
	if err = os.WriteFile(oversizedPath, make([]byte, providerBrokerMaxBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	broker.process(context.Background(), oversizedID, oversizedPath)
	if calls.Load() != 0 {
		t.Fatalf("invalid requests reached provider %d times", calls.Load())
	}
}

func writeBrokerRequest(t *testing.T, inbox, id string, payload map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(inbox, id+".json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
