package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type providerUsage struct {
	Requests     int64 `json:"requests"`
	Failures     int64 `json:"failures"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type providerProfile struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Model     string          `json:"model,omitempty"`
	BaseURL   string          `json:"base_url,omitempty"`
	APIKeyEnv string          `json:"api_key_env,omitempty"`
	Enabled   bool            `json:"enabled"`
	Priority  int             `json:"priority"`
	Usage     providerUsage   `json:"usage"`
	Models    []providerModel `json:"models,omitempty"`
}

type providerModel struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

type localProviderConfig struct {
	BaseURL     string          `json:"base_url"`
	Model       string          `json:"model"`
	DisplayName string          `json:"display_name"`
	APIKeys     []string        `json:"api_keys"`
	Models      []providerModel `json:"models"`
}

func readLocalProviderConfig() localProviderConfig {
	path := strings.TrimSpace(os.Getenv("REVERSE_ANALYZER_PROVIDER_CONFIG"))
	if path == "" {
		path = filepath.Join("config", "provider.local.json")
	}
	var cfg localProviderConfig
	_ = readFileJSON(path, &cfg)
	return cfg
}

func providerAPIKeys(profile providerProfile) []string {
	values := []string{}
	if raw := strings.TrimSpace(os.Getenv("OPENAI_API_KEYS")); raw != "" {
		values = append(values, strings.Split(raw, ",")...)
	}
	if profile.APIKeyEnv != "" {
		if key := strings.TrimSpace(os.Getenv(profile.APIKeyEnv)); key != "" {
			values = append(values, key)
		}
	}
	if len(values) == 0 {
		values = append(values, readLocalProviderConfig().APIKeys...)
	}
	result, seen := []string{}, map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func defaultProviderProfiles() []providerProfile {
	local := readLocalProviderConfig()
	model := env("OPENAI_MODEL", local.Model)
	if model == "" {
		model = "gpt-4.1-mini"
	}
	baseURL := env("OPENAI_BASE_URL", local.BaseURL)
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return []providerProfile{
		{Name: "rule_based", Kind: "local", Enabled: true, Priority: 0},
		{Name: "openai_compatible", Kind: "openai-compatible", Model: model, Models: normalizeProviderModels(local.Models, model), BaseURL: baseURL, APIKeyEnv: "OPENAI_API_KEY", Enabled: os.Getenv("REVERSE_ANALYZER_OPENAI_ENABLED") != "" || len(local.APIKeys) > 0, Priority: 10},
	}
}

func normalizeProviderModels(items []providerModel, legacy string) []providerModel {
	result := []providerModel{}
	seen := map[string]bool{}
	for _, item := range items {
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" || seen[item.ID] {
			continue
		}
		seen[item.ID] = true
		result = append(result, item)
	}
	if len(result) == 0 && strings.TrimSpace(legacy) != "" {
		result = append(result, providerModel{ID: strings.TrimSpace(legacy), DisplayName: strings.TrimSpace(legacy), Priority: 10, Enabled: true})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Priority < result[j].Priority })
	return result
}

func preferredProviderModel(profile *providerProfile) bool {
	profile.Models = normalizeProviderModels(profile.Models, profile.Model)
	for _, item := range profile.Models {
		if item.Enabled {
			profile.Model = item.ID
			return true
		}
	}
	profile.Model = ""
	return false
}

func (s *Server) providerProfiles() []providerProfile {
	items := defaultProviderProfiles()
	configured := map[string]providerProfile{}
	if s.db != nil && s.dbErr == nil {
		rows, err := s.db.Query(`SELECT payload FROM provider_configs WHERE workspace_id=$1`, s.cfg.Workspace)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var payload []byte
				var profile providerProfile
				if rows.Scan(&payload) == nil && json.Unmarshal(payload, &profile) == nil {
					configured[profile.Name] = profile
				}
			}
		}
	} else {
		var stored []providerProfile
		_ = readFileJSON(filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "providers.json"), &stored)
		for _, profile := range stored {
			configured[profile.Name] = profile
		}
	}
	for i, profile := range items {
		if override, ok := configured[profile.Name]; ok {
			items[i] = override
			delete(configured, profile.Name)
		}
	}
	for i := range items {
		preferredProviderModel(&items[i])
	}
	for _, profile := range configured {
		items = append(items, profile)
	}
	for i := range items {
		preferredProviderModel(&items[i])
	}
	usage := s.providerUsage()
	for i := range items {
		items[i].Usage = usage[items[i].Name]
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Priority < items[j].Priority })
	return items
}

func (s *Server) providerUsage() map[string]providerUsage {
	usage := map[string]providerUsage{}
	if s.db != nil && s.dbErr == nil {
		rows, err := s.db.Query(`SELECT provider,requests,failures,input_tokens,output_tokens FROM provider_usage WHERE workspace_id=$1`, s.cfg.Workspace)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var name string
				var value providerUsage
				if rows.Scan(&name, &value.Requests, &value.Failures, &value.InputTokens, &value.OutputTokens) == nil {
					usage[name] = value
				}
			}
		}
	} else {
		_ = readFileJSON(filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "provider-usage.json"), &usage)
	}
	return usage
}

func validateProvider(profile providerProfile) error {
	preferredProviderModel(&profile)
	if profile.Name == "" || profile.Kind == "" {
		return errors.New("provider name and kind are required")
	}
	if profile.Name == "rule_based" && (!profile.Enabled || profile.Kind != "local") {
		return errors.New("rule_based must remain an enabled local fallback")
	}
	if profile.Kind != "local" && profile.Kind != "openai-compatible" {
		return errors.New("supported provider kinds are local and openai-compatible")
	}
	if profile.Kind == "openai-compatible" {
		if profile.Model == "" {
			return errors.New("openai-compatible provider requires at least one enabled model")
		}
		parsed, err := url.ParseRequestURI(profile.BaseURL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			return errors.New("openai-compatible provider requires a valid HTTP(S) base_url")
		}
		if profile.APIKeyEnv == "" || strings.ContainsAny(profile.APIKeyEnv, " =\t\r\n") {
			return errors.New("api_key_env must name one environment variable")
		}
	}
	return nil
}

func (s *Server) saveProvider(profile providerProfile) error {
	preferredProviderModel(&profile)
	if err := validateProvider(profile); err != nil {
		return err
	}
	profile.Usage = providerUsage{}
	if s.dbErr != nil {
		return s.dbErr
	}
	if s.db != nil {
		payload, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		_, err = s.db.Exec(`INSERT INTO provider_configs(workspace_id,name,updated_at,payload) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(workspace_id,name) DO UPDATE SET updated_at=excluded.updated_at,payload=excluded.payload`, s.cfg.Workspace, profile.Name, now(), string(payload))
		return err
	}
	items := s.providerProfiles()
	replaced := false
	for i := range items {
		items[i].Usage = providerUsage{}
		if items[i].Name == profile.Name {
			items[i] = profile
			replaced = true
		}
	}
	if !replaced {
		items = append(items, profile)
	}
	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "providers.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return writeFileJSON(path, items)
}

func (s *Server) selectProvider(requested string) (providerProfile, bool) {
	items := s.providerProfiles()
	for _, profile := range items {
		if profile.Name == requested && s.providerReady(profile) {
			return profile, false
		}
	}
	for _, profile := range items {
		if s.providerReady(profile) {
			return profile, requested != "" && requested != profile.Name
		}
	}
	return defaultProviderProfiles()[0], requested != "" && requested != "rule_based"
}

func (s *Server) providerReady(profile providerProfile) bool {
	modelReady := profile.Kind == "local" || preferredProviderModel(&profile)
	return profile.Enabled && modelReady && (profile.Kind == "local" || len(providerAPIKeys(profile)) > 0)
}

func (s *Server) testProvider(ctx context.Context, profile providerProfile) (map[string]any, error) {
	if profile.Kind == "local" {
		return map[string]any{"name": profile.Name, "status": "ready", "network_call": false, "model": profile.Model}, nil
	}
	keys := providerAPIKeys(profile)
	if len(keys) == 0 {
		return map[string]any{"name": profile.Name, "status": "dependency-gated", "network_call": false, "missing": profile.APIKeyEnv}, nil
	}
	endpoint := strings.TrimRight(profile.BaseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for slot, key := range keys {
		current := req.Clone(ctx)
		current.Header.Set("Authorization", "Bearer "+key)
		response, callErr := client.Do(current)
		if callErr != nil {
			if slot+1 < len(keys) {
				continue
			}
			return nil, callErr
		}
		status := response.StatusCode
		response.Body.Close()
		if status >= 200 && status < 300 {
			return map[string]any{"name": profile.Name, "status": "ready", "network_call": true, "model": profile.Model, "endpoint": endpoint, "key_slot": slot + 1}, nil
		}
		if status != 401 && status != 403 && status != 429 && status < 500 {
			return nil, fmt.Errorf("provider returned HTTP %d", status)
		}
		if slot+1 == len(keys) {
			return nil, fmt.Errorf("provider returned HTTP %d after all credential slots", status)
		}
	}
	return nil, errors.New("provider credential slots exhausted")
}

func (s *Server) recordProvider(name string, failed bool) {
	s.recordProviderUsage(name, 1, failed, 0, 0)
}

func (s *Server) recordProviderUsage(name string, requests int64, failed bool, inputTokens, outputTokens int64) {
	if requests < 1 {
		requests = 1
	}
	if s.db != nil && s.dbErr == nil {
		failure := 0
		if failed {
			failure = 1
		}
		_, _ = s.db.Exec(`INSERT INTO provider_usage(workspace_id,provider,requests,failures,input_tokens,output_tokens) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workspace_id,provider) DO UPDATE SET requests=provider_usage.requests+$3,failures=provider_usage.failures+$4,input_tokens=provider_usage.input_tokens+$5,output_tokens=provider_usage.output_tokens+$6`, s.cfg.Workspace, name, requests, failure, inputTokens, outputTokens)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.cfg.Workspace, ".reverse_analyzer", "provider-usage.json")
	usage := map[string]providerUsage{}
	_ = readFileJSON(path, &usage)
	value := usage[name]
	value.Requests += requests
	if failed {
		value.Failures++
	}
	value.InputTokens += inputTokens
	value.OutputTokens += outputTokens
	usage[name] = value
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	_ = writeFileJSON(path, usage)
}
