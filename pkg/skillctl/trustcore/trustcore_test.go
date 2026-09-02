package trustcore

import (
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// TestKindFromSignedEnvelope pins the classifier over the four signed shapes plus
// the unclassifiable (empty / no-discriminator) case. The kind is derived ONLY
// from the signed discriminator field — the classifier never sees a carrier tag,
// filename, or annotation.
func TestKindFromSignedEnvelope(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]any
		want artifact.EventKind
	}{
		{"revoke", map[string]any{"revoked_by": "id:gov", "bundle_digest": "sha256:x"}, artifact.KindRevoke},
		{"attest", map[string]any{"reviewer_id": "id:rev", "governance_level": "green"}, artifact.KindAttest},
		{"install", map[string]any{"installed_on_host": "host-1"}, artifact.KindInstall},
		{"admit", map[string]any{"admitted_by_identity": "id:a", "signatures": []any{}}, artifact.KindAdmit},
		// Unclassifiable / "ambiguous" in the sense of carrying no discriminator: a
		// bare envelope with only anchor/metadata fields is unknown ("") and dropped.
		{"empty", map[string]any{}, ""},
		{"no-discriminator", map[string]any{"bundle_digest": "sha256:x", "occurred_at": "2026-01-01T00:00:00Z"}, ""},
		// An empty-string discriminator is treated as ABSENT (carrier can't neuter a
		// classification by blanking the field either — it just becomes unknown).
		{"blank-revoked_by", map[string]any{"revoked_by": ""}, ""},
		{"nil-env", nil, ""},
		// revoke takes precedence (fail-safe toward DENY) if a degenerate envelope
		// carries a revoke field alongside another discriminator.
		{"revoke-precedence", map[string]any{"revoked_by": "id:gov", "reviewer_id": "id:rev"}, artifact.KindRevoke},
	}
	for _, c := range cases {
		if got := KindFromSignedEnvelope(c.env); got != c.want {
			t.Errorf("%s: KindFromSignedEnvelope(%v) = %q, want %q", c.name, c.env, got, c.want)
		}
	}
}

func TestSignedDigest(t *testing.T) {
	if got := SignedDigest(map[string]any{"bundle_digest": "sha256:abc"}); got != "sha256:abc" {
		t.Errorf("SignedDigest = %q, want sha256:abc", got)
	}
	if got := SignedDigest(map[string]any{}); got != "" {
		t.Errorf("SignedDigest(no digest) = %q, want empty", got)
	}
	if got := SignedDigest(nil); got != "" {
		t.Errorf("SignedDigest(nil) = %q, want empty", got)
	}
	if got := SignedDigest(map[string]any{"bundle_digest": 42}); got != "" {
		t.Errorf("SignedDigest(non-string) = %q, want empty", got)
	}
}

func TestValidDigest(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	if !ValidDigest(good) {
		t.Errorf("ValidDigest(%q) = false, want true", good)
	}
	for _, bad := range []string{
		"",
		"sha256:short",
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("A", 64), // uppercase not allowed
		"md5:" + strings.Repeat("a", 64),
		strings.Repeat("a", 64), // missing prefix
	} {
		if ValidDigest(bad) {
			t.Errorf("ValidDigest(%q) = true, want false", bad)
		}
	}
}
