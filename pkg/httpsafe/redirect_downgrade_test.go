package httpsafe

import (
	"net/http"
	"testing"
)

// TestNoCrossHostRedirect_RejectsSchemeDowngrade pins the challenge-gate LOW fix:
// even on the SAME host, an https→http downgrade redirect must fail closed, so a
// trust-path request cannot be dropped onto plaintext (MITM / suppression).
func TestNoCrossHostRedirect_RejectsSchemeDowngrade(t *testing.T) {
	mkReq := func(raw string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatalf("NewRequest %s: %v", raw, err)
		}
		return r
	}
	via := []*http.Request{mkReq("https://registry.example/api")}

	if err := NoCrossHostRedirect(mkReq("http://registry.example/api"), via); err == nil {
		t.Error("expected refusal of same-host https→http downgrade redirect, got nil")
	}
	// A same-host https→https redirect must still be allowed (no over-blocking).
	if err := NoCrossHostRedirect(mkReq("https://registry.example/other"), via); err != nil {
		t.Errorf("same-host https→https redirect should be allowed, got %v", err)
	}
}
