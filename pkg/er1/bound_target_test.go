package er1

import (
	"strings"
	"testing"
)

func TestResolveBoundTargetPreservesOriginAndPrefix(t *testing.T) {
	t.Setenv("ER1_API_URL", "https://upload.example/TenantA/upload_2")
	t.Setenv("ER1_VERIFY_SSL", "false")
	for _, tc := range []struct {
		raw, want string
		verify    bool
	}{
		{"prod", "https://onboarding.guide:443", true},
		{"local", "https://127.0.0.1:8081", false},
		{"stage", "https://upload.example:443/TenantA", true},
		{"HTTPS://UPLOAD.EXAMPLE/TenantA", "https://upload.example:443/TenantA", true},
		{"https://a.example/TenantA/upload-history", "https://a.example:443/TenantA/upload-history", true},
		{"https://a.example/prefix%2FCase/upload_2", "https://a.example:443/prefix%2FCase", true},
	} {
		got, verify, err := ResolveBoundTarget(tc.raw)
		if err != nil || got != tc.want || verify != tc.verify {
			t.Fatalf("target=%q result=%q,%v,%v", tc.raw, got, verify, err)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8081", "https://synthetic-secret@a.example/upload_2", "https://a.example/upload_2?synthetic-secret", "https://a.example/#synthetic-secret", "https://a.example:0"} {
		got, _, err := ResolveBoundTarget(raw)
		if err == nil || got != "" || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("unsafe target result=%q,%v", got, err)
		}
	}
	t.Setenv("ER1_API_URL", "https://a.example/upload_2?synthetic-secret")
	if _, _, err := ResolveBoundTarget("stage"); err == nil {
		t.Fatal("invalid original URL hidden by suffix handling")
	}
}
