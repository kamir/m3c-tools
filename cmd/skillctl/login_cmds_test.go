package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolveLoginBase(t *testing.T) {
	// default → public SaaS (the Alice bug: was localhost)
	if got := resolveLoginBase("", ""); got != "https://onboarding.guide" {
		t.Fatalf("default base = %q, want https://onboarding.guide", got)
	}
	// explicit --base-url wins (trailing slash trimmed)
	if got := resolveLoginBase("https://stage.example/", ""); got != "https://stage.example" {
		t.Fatalf("flag base = %q, want https://stage.example", got)
	}
	// ER1_API_URL (upload URL) → stripped to root
	if got := resolveLoginBase("", "https://127.0.0.1:8081/upload_2"); got != "https://127.0.0.1:8081" {
		t.Fatalf("env base = %q, want https://127.0.0.1:8081", got)
	}
	// flag beats env
	if got := resolveLoginBase("https://onboarding.guide", "https://127.0.0.1:8081/upload_2"); got != "https://onboarding.guide" {
		t.Fatalf("flag should beat env, got %q", got)
	}
}

func TestLoginRejectsInvalidTargetBeforeCallback(t *testing.T) {
	for _, raw := range []string{"http://remote.example", "https://synthetic:secret@a.example", "https://a.example/upload_2?synthetic-secret", "https://a.example/upload_2#synthetic-secret", "https://a.example/\\evil"} {
		t.Run(raw, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("ER1_API_URL", raw)
			var out, errb bytes.Buffer
			code := runLogin([]string{"--no-browser", "--timeout", "1ms"}, &out, &errb)
			if code != 1 || out.Len() != 0 || strings.Contains(errb.String(), "synthetic-secret") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errb.String())
			}
		})
	}
}
