package timetracking

import (
	"net/http"
	"testing"
	"time"
)

// TestNewPLMClient_NonLoopbackForcesVerifyingTransport pins AUDIT-0001
// Befund 1.2/2.8: pkg/er1's loopback-only VerifySSL=false policy is applied
// to ER1_API_URL, but M3C_PLM_BASE_URL can point the PLM client at a DIFFERENT
// host while VerifySSL=false travels along unchanged. Before the fix,
// NewPLMClient set InsecureSkipVerify for any base; now only a loopback base
// may skip TLS verification.
func TestNewPLMClient_NonLoopbackForcesVerifyingTransport(t *testing.T) {
	c := NewPLMClient(PLMConfig{
		BaseURL:   "https://plm.example.com",
		APIKey:    "k",
		VerifySSL: false,
		Timeout:   5 * time.Second,
	})
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", c.client.Transport)
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("non-loopback base with VerifySSL=false must get a VERIFYING transport")
	}
	if c.client.CheckRedirect == nil {
		t.Error("PLM client must carry a CheckRedirect policy (AUDIT-0001 Befund 1.1)")
	}
}

// TestNewPLMClient_LoopbackKeepsDevSkip guards the dev workflow: a local
// aims-core with a self-signed cert stays reachable.
func TestNewPLMClient_LoopbackKeepsDevSkip(t *testing.T) {
	c := NewPLMClient(PLMConfig{BaseURL: "https://127.0.0.1:8443", VerifySSL: false})
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", c.client.Transport)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("loopback base with VerifySSL=false should keep the dev TLS skip")
	}
}

func TestPLMBaseIsLoopback(t *testing.T) {
	cases := []struct {
		base string
		want bool
	}{
		{"https://127.0.0.1:8443", true},
		{"https://localhost", true},
		{"https://localhost:8081", true},
		{"https://plm.example.com", false},
		{"https://192.168.1.7:8081", false}, // RFC1918 is NOT loopback; mirrors pkg/er1 policy
		{"", false},
		{"::::", false},
	}
	for _, tc := range cases {
		if got := plmBaseIsLoopback(tc.base); got != tc.want {
			t.Errorf("plmBaseIsLoopback(%q) = %v, want %v", tc.base, got, tc.want)
		}
	}
}
