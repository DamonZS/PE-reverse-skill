package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultProviderPrefersReadyExternalModel(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "provider.local.json")
	if err := os.WriteFile(configPath, []byte(`{"base_url":"https://model.example/v1","model":"gpt-test","api_keys":["test-key"],"models":[{"id":"gpt-test","priority":10,"enabled":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REVERSE_ANALYZER_PROVIDER_CONFIG", configPath)
	s := &Server{cfg: Config{Workspace: t.TempDir()}}

	profile, fallback := s.selectProvider("")

	if profile.Name != "openai_compatible" || profile.Model != "gpt-test" || fallback {
		t.Fatalf("unexpected default provider: %#v fallback=%v", profile, fallback)
	}
}
