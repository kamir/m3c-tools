package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

func TestBoundRegistryEnvironmentToken(t *testing.T) {
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-write-value")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "synthetic-read-value")
	for _, tc := range []struct {
		name, target, pin string
		allowed           bool
	}{
		{"default-port", "https://registry.invalid/api/skills", "https://registry.invalid:443", true},
		{"case", "https://REGISTRY.invalid/api/skills", "https://registry.invalid", true},
		{"loopback", "http://127.0.0.1:1234/api/skills", "http://127.0.0.1:1234", true},
		{"ipv6", "http://[::1]:1234/api/skills", "http://[::1]:1234", true},
		{"missing-pin", "https://registry.invalid/api/skills", "", false},
		{"wrong-host", "https://foreign.invalid/api/skills", "https://registry.invalid", false},
		{"wrong-port", "https://registry.invalid:444/api/skills", "https://registry.invalid", false},
		{"downgrade", "http://registry.invalid/api/skills", "https://registry.invalid", false},
		{"userinfo", "https://user:synthetic-password@registry.invalid/api/skills", "https://registry.invalid", false},
		{"query", "https://registry.invalid/api/skills?token=synthetic-password", "https://registry.invalid", false},
		{"fragment", "https://registry.invalid/api/skills#suffix", "https://registry.invalid", false},
		{"pin-path", "https://registry.invalid/api/skills", "https://registry.invalid/path", false},
		{"pin-userinfo", "https://registry.invalid/api/skills", "https://user:pass@registry.invalid", false},
		{"private-http", "http://192.168.1.1/api/skills", "http://192.168.1.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", tc.pin)
			for _, mode := range []artifact.AccessMode{artifact.ModeRead, artifact.ModeWrite} {
				token, err := boundRegistryToken(tc.target, mode)
				if tc.allowed {
					want := "synthetic-write-value"
					if mode == artifact.ModeRead {
						want = "synthetic-read-value"
					}
					if err != nil || token != want {
						t.Fatalf("allowed pin failed: %v", err)
					}
				} else if err == nil || token != "" {
					t.Fatal("unbound token escaped")
				}
			}
			if !tc.allowed && registryToken(tc.target, artifact.ModeRead) != "" {
				t.Fatal("read-client fallback leaked token")
			}
		})
	}
	t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", "https://registry.invalid")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")
	token, err := boundRegistryToken("https://registry.invalid/api/skills", artifact.ModeRead)
	if err != nil || token != "synthetic-write-value" {
		t.Fatal("read fallback lost")
	}
}

func TestBoundRegistryAnonymousNativeDisabled(t *testing.T) {
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_REGISTRY_TOKEN", "")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")
	for _, target := range []string{"https://registry.invalid/api/skills", "http://127.0.0.1:1234/api/skills", "http://192.168.1.1/api/skills"} {
		token, err := boundRegistryToken(target, artifact.ModeRead)
		if err != nil || token != "" {
			t.Fatalf("anonymous lookup failed: %v", err)
		}
	}
}

func TestAttestUnboundEnvironmentFailsBeforeKeyLoad(t *testing.T) {
	t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-write-value")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")
	t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", "")
	var stdout, stderr bytes.Buffer
	code := runAttest([]string{"--json", "--level", "green", "--rationale", "fixture", "--reviewer-id", "id:fixture", "--key", filepath.Join(t.TempDir(), "missing.private"), "--registry", "https://registry.invalid/api/skills", validDigestForTest}, &stdout, &stderr)
	var receipt attestReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if code != 1 || receipt.OK || !strings.Contains(receipt.Error, "M3C_REGISTRY_TOKEN_ORIGIN") || strings.Contains(stdout.String()+stderr.String(), "synthetic-write-value") || strings.Contains(receipt.Error, "missing.private") {
		t.Fatalf("invalid fail-before-key receipt: %+v", receipt)
	}
}

func TestBoundRegistryHeadersActualHTTP(t *testing.T) {
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-write-value")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "synthetic-read-value")
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		want := "Bearer synthetic-read-value"
		if r.Method == http.MethodPost {
			want = "Bearer synthetic-write-value"
		}
		if r.Header.Get("Authorization") != want {
			t.Error("missing expected synthetic credential tier")
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"attestation_id":"synthetic-receipt"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"fixture","versions":[]}`))
	}))
	t.Cleanup(server.Close)
	t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", server.URL)
	_, err := newRegistryClient(server.URL, server.Client()).ResolveByName(context.Background(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	private, _, _ := makeReviewerKeys(t, t.TempDir())
	var stdout, stderr bytes.Buffer
	code := runAttest([]string{"--json", "--level", "green", "--rationale", "fixture", "--reviewer-id", "id:fixture", "--key", private, "--registry", server.URL, validDigestForTest}, &stdout, &stderr)
	if code != 0 || received.Load() != 2 {
		t.Fatalf("code%d requests%d stderr%s", code, received.Load(), &stderr)
	}
}

func TestExplainUnauthorizedDescribesOriginPolicyWithoutPlatformAssumptions(t *testing.T) {
	var stderr bytes.Buffer
	returned := explainUnauthorized(&stderr, "https://registry.invalid/api/skills", false, errRegistryUnauthorized)
	if returned != errRegistryUnauthorized {
		t.Fatal("error identity changed")
	}
	for _, required := range []string{"NO token was sent", "M3C_REGISTRY_TOKEN_ORIGIN", "M3C_REGISTRY_RO_TOKEN", "skillctl token set --backend registry", "native storage disabled"} {
		if !strings.Contains(stderr.String(), required) {
			t.Fatalf("missing actionable guidance %q: %s", required, &stderr)
		}
	}
	for _, forbidden := range []string{"no credential is provisioned", "security add-generic-password"} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("misleading guidance %q", forbidden)
		}
	}
}

func TestAttestAnonymousTransportRequiresHTTPSOrLoopbackBeforeKeyLoad(t *testing.T) {
	t.Setenv("M3C_REGISTRY_TOKEN", "")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")
	t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", "")
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	for _, target := range []string{"http://192.168.0.131:9100/api/skills", "http://169.254.1.1/api/skills", "http://registry.invalid/api/skills"} {
		var stdout, stderr bytes.Buffer
		code := runAttest([]string{"--json", "--level", "green", "--rationale", "fixture", "--reviewer-id", "id:fixture", "--key", filepath.Join(t.TempDir(), "missing.private"), "--registry", target, validDigestForTest}, &stdout, &stderr)
		var receipt attestReceipt
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if code != 2 || receipt.OK || !strings.Contains(receipt.Error, "HTTPS or loopback HTTP") || strings.Contains(receipt.Error, "missing.private") {
			t.Fatalf("unsafe anonymous transport: code%d receipt%+v", code, receipt)
		}
	}
	for _, target := range []string{"https://registry.invalid/api/skills", "http://127.0.0.1:1234/api/skills", "http://localhost:1234/api/skills", "http://[::1]:1234/api/skills"} {
		if err := validateAttestRegistryURL(target); err != nil {
			t.Fatalf("valid transport refused: %v", err)
		}
	}
}
