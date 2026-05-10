package skillgate

import (
	"strings"
	"testing"
)

// TestCanonicalize_DeterministicAcrossCalls — same token → same bytes.
func TestCanonicalize_DeterministicAcrossCalls(t *testing.T) {
	tok := &Token{
		Schema:         "m3c-skill-capability/v1",
		TokenID:        "ct:01HZTESTTESTTESTTESTTESTTE",
		IssuedAt:       "2026-05-10T00:00:00Z",
		ExpiresAt:      "2026-05-10T00:05:00Z",
		BundleDigest:   "sha256:abc",
		SkillName:      "demo",
		SkillVersion:   "0.1.0",
		CallerIdentity: "id:tester",
		CallerSession:  "sess:01HZSESSIONSESSIONSESSIO",
		Envelope: TokenEnvelope{
			Capabilities:        []string{"fs:read", "egress"},
			EgressAllowlist:     []string{"api.example.com:443"},
			SubprocessAllowlist: []string{"git", "bash"},
		},
		RegistryKeyID: "registry-2026",
	}
	b1, err := CanonicalizeToken(tok)
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	b2, err := CanonicalizeToken(tok)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Errorf("non-deterministic canonical bytes:\n  b1=%q\n  b2=%q", b1, b2)
	}
}

// TestCanonicalize_SortsLists — capability/allowlist/denylist must be sorted.
func TestCanonicalize_SortsLists(t *testing.T) {
	unsorted := &Token{
		Schema:         "m3c-skill-capability/v1",
		TokenID:        "ct:01HZTESTTESTTESTTESTTESTTE",
		IssuedAt:       "2026-05-10T00:00:00Z",
		ExpiresAt:      "2026-05-10T00:05:00Z",
		BundleDigest:   "sha256:abc",
		SkillName:      "demo",
		SkillVersion:   "0.1.0",
		CallerIdentity: "id:tester",
		CallerSession:  "sess:01HZSESSIONSESSIONSESSIO",
		Envelope: TokenEnvelope{
			Capabilities: []string{"egress", "fs:read"}, // wrong alpha order
		},
		RegistryKeyID: "registry-2026",
	}
	b, err := CanonicalizeToken(unsorted)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	// The line should be sorted alphabetically: egress,fs:read.
	if !strings.Contains(string(b), "envelope_capabilities=egress,fs:read") {
		t.Errorf("expected sorted capability list in canonical bytes, got:\n%s", b)
	}
}

// TestCanonicalize_NewlineTerminated — every line ends with \n; no trailing
// junk after the last field.
func TestCanonicalize_NewlineTerminated(t *testing.T) {
	tok := &Token{
		Schema:         "m3c-skill-capability/v1",
		TokenID:        "ct:01HZTESTTESTTESTTESTTESTTE",
		IssuedAt:       "2026-05-10T00:00:00Z",
		ExpiresAt:      "2026-05-10T00:05:00Z",
		BundleDigest:   "sha256:abc",
		SkillName:      "demo",
		SkillVersion:   "0.1.0",
		CallerIdentity: "id:tester",
		CallerSession:  "sess:01HZSESSIONSESSIONSESSIO",
		RegistryKeyID:  "registry-2026",
	}
	b, err := CanonicalizeToken(tok)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Errorf("expected canonical bytes to end with \\n, got tail=%q", b[max(0, len(b)-10):])
	}
	// No double newlines (would indicate stray empty line):
	if strings.Contains(string(b), "\n\n") {
		t.Errorf("canonical bytes contain '\\n\\n': %q", b)
	}
}

// max helper for older Go versions; on 1.21+ this is a builtin.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
