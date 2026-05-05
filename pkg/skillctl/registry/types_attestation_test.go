package registry

// Lock the additive wire shape introduced by SPEC-0188 stream S8
// (BundleMeta.Attestations + BundleMeta.CurrentGovernance). The S7-owned
// client_test.go covers everything else; this file only exercises the new
// fields so a future schema change to BundleMeta is caught loudly.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestBundleMeta_DecodesAttestationsAndCurrentGovernance(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bundle": map[string]any{
				"bundle_digest": "sha256:abc",
				"status":        "admitted",
			},
			"signatures": []map[string]any{
				{"role": "author", "identity_id": "id:kamir@m3c", "signature_b64": "AAAA"},
			},
			// New: §S8 wire-shape extension.
			"current_governance": "green",
			"attestations": []map[string]any{
				{
					"attestation_id": "att:01HZZ",
					"level":          "green",
					"reviewer_id":    "id:reviewer@m3c",
					"attested_at":    "2026-05-05T20:00:00Z",
					"rationale":      "Read-only ER1 query; no writes.",
					"signature_b64":  "ZmFrZXNpZw==",
					"status":         "active",
				},
				{
					"attestation_id": "att:01HZY",
					"level":          "yellow",
					"reviewer_id":    "id:reviewer-old@m3c",
					"attested_at":    "2026-04-30T00:00:00Z",
				},
			},
		})
	})

	c := fs.client()
	meta, err := c.GetBundleMeta(context.Background(), "sha256:abc")
	if err != nil {
		t.Fatalf("GetBundleMeta: %v", err)
	}
	if meta.CurrentGovernance != "green" {
		t.Errorf("CurrentGovernance = %q, want green", meta.CurrentGovernance)
	}
	if len(meta.Attestations) != 2 {
		t.Fatalf("Attestations len = %d, want 2", len(meta.Attestations))
	}
	a0 := meta.Attestations[0]
	if a0.AttestationID != "att:01HZZ" || a0.Level != "green" || a0.ReviewerID != "id:reviewer@m3c" {
		t.Errorf("Attestations[0] wrong: %+v", a0)
	}
	if a0.SignatureB64 != "ZmFrZXNpZw==" {
		t.Errorf("Attestations[0].SignatureB64 = %q", a0.SignatureB64)
	}
	if meta.Attestations[1].Level != "yellow" {
		t.Errorf("Attestations[1].Level = %q", meta.Attestations[1].Level)
	}
}

func TestBundleMeta_OmittedAttestationsIsAllowed(t *testing.T) {
	// Older / stub registries may not surface attestations. The verifier
	// gates on CurrentGovernance == "" → red anyway, but the client must
	// not refuse a response missing those fields outright.
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bundle":     map[string]any{"bundle_digest": "sha256:abc"},
			"signatures": []map[string]any{},
		})
	})
	c := fs.client()
	meta, err := c.GetBundleMeta(context.Background(), "sha256:abc")
	if err != nil {
		t.Fatalf("GetBundleMeta: %v", err)
	}
	if meta.CurrentGovernance != "" {
		t.Errorf("CurrentGovernance should be empty when omitted, got %q", meta.CurrentGovernance)
	}
	if len(meta.Attestations) != 0 {
		t.Errorf("Attestations should be empty when omitted, got %d", len(meta.Attestations))
	}
}
