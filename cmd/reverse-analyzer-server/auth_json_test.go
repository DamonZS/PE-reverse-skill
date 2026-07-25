package main

import (
	"encoding/json"
	"testing"
)

func TestIdentityUsesFrontendJSONFieldNames(t *testing.T) {
	payload, err := json.Marshal(identity{Subject: "admin", Role: "admin", Workspace: "/workspace", Source: "environment"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["role"] != "admin" || decoded["subject"] != "admin" {
		t.Fatalf("frontend identity fields missing: %s", payload)
	}
	if _, exists := decoded["Role"]; exists {
		t.Fatalf("unexpected Go field casing: %s", payload)
	}
}
