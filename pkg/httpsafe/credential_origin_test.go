package httpsafe

import (
	"net/http"
	"strings"
	"testing"
)

func TestCredentialRedirectOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, origin, target string
		refuse, keep         bool
	}{
		{"same origin", "https://registry.test/a", "https://registry.test/b", false, true},
		{"default HTTPS port", "https://registry.test/a", "https://REGISTRY.test:443/b", false, true},
		{"default HTTP port", "http://localhost/a", "http://localhost:80/b", false, true},
		{"different port", "https://registry.test/a", "https://registry.test:8443/b", false, false},
		{"zero port", "https://registry.test/a", "https://registry.test:0/b", false, false},
		{"different host", "https://registry.test/a", "https://collector.test/b", false, false},
		{"downgrade", "https://registry.test/a", "http://registry.test/b", true, false},
		{"upgrade changes origin", "http://registry.test/a", "https://registry.test/b", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin, err := http.NewRequest(http.MethodGet, tc.origin, nil)
			if err != nil {
				t.Fatal(err)
			}
			target, err := http.NewRequest(http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, header := range sensitiveHeaders {
				target.Header.Set(header, "synthetic-credential")
			}
			err = NoCredentialRedirect(target, []*http.Request{origin})
			if (err != nil) != tc.refuse {
				t.Fatalf("redirect error = %v, refusal wanted = %v", err, tc.refuse)
			}
			if tc.refuse {
				return
			}
			for _, header := range sensitiveHeaders {
				if got := target.Header.Get(header); (got != "") != tc.keep {
					t.Errorf("credential presence for %s = %v, want %v", header, got != "", tc.keep)
				}
			}
		})
	}
}

func TestCredentialRedirectRefusesIntermediateDowngrade(t *testing.T) {
	first, _ := http.NewRequest(http.MethodGet, "http://registry.test/a", nil)
	secure, _ := http.NewRequest(http.MethodGet, "https://registry.test/b", nil)
	last, _ := http.NewRequest(http.MethodGet, "http://registry.test/c", nil)
	if err := NoCredentialRedirect(last, []*http.Request{first, secure}); err == nil {
		t.Fatal("an intermediate HTTPS hop must not redirect back to HTTP")
	}
}

func TestCredentialRedirectRefusesCrossOriginBody(t *testing.T) {
	origin, _ := http.NewRequest(http.MethodPost, "https://registry.test/upload", strings.NewReader("synthetic-payload"))
	target, _ := http.NewRequest(http.MethodPost, "https://collector.test/upload", strings.NewReader("synthetic-payload"))
	if err := NoCredentialRedirect(target, []*http.Request{origin}); err == nil {
		t.Fatal("redirect must not forward an upload body to another origin")
	}
}
