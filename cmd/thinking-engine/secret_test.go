package main

import "testing"

func TestHMACSecretFromEnv_Required(t *testing.T) {
	t.Setenv("THINKING_ENGINE_SECRET", "")
	_, err := hmacSecretFromEnv("THINKING_ENGINE_SECRET", false, "abc")
	if err == nil {
		t.Fatal("empty secret without --dev must fail")
	}
}

func TestHMACSecretFromEnv_DevFallback(t *testing.T) {
	t.Setenv("THINKING_ENGINE_SECRET", "")
	got, err := hmacSecretFromEnv("THINKING_ENGINE_SECRET", true, "deadbeef")
	if err != nil {
		t.Fatalf("dev fallback: %v", err)
	}
	if string(got) != "dev-deadbeef" {
		t.Errorf("secret = %q, want dev-deadbeef", got)
	}
}

func TestHMACSecretFromEnv_UsesEnv(t *testing.T) {
	t.Setenv("THINKING_ENGINE_SECRET", "real-secret")
	got, err := hmacSecretFromEnv("THINKING_ENGINE_SECRET", false, "abc")
	if err != nil {
		t.Fatalf("env secret: %v", err)
	}
	if string(got) != "real-secret" {
		t.Errorf("secret = %q, want real-secret", got)
	}
}
