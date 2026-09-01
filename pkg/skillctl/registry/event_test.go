package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── Canonical bytes ───────────────────────────────────────────────────────

func TestCanonicalEventBytes_SortedKeys_NoEnvelopeSignature_NoTrailingNL(t *testing.T) {
	ev := map[string]any{
		"zeta":               "last",
		"alpha":              "first",
		"middle":             42,
		EnvelopeSignatureField: "should-be-stripped",
	}
	got, err := CanonicalEventBytes(ev)
	if err != nil {
		t.Fatalf("CanonicalEventBytes: %v", err)
	}
	want := `{"alpha":"first","middle":42,"zeta":"last"}`
	if string(got) != want {
		t.Errorf("canonical bytes = %q, want %q", got, want)
	}
	if strings.Contains(string(got), EnvelopeSignatureField) {
		t.Errorf("envelope_signature leaked into canonical bytes: %s", got)
	}
	if n := len(got); n > 0 && got[n-1] == '\n' {
		t.Errorf("canonical bytes have trailing newline")
	}
}

func TestCanonicalEventBytes_NestedKeysSortedAtEveryLevel(t *testing.T) {
	ev := map[string]any{
		"outer_b": map[string]any{"z": 1, "a": 2},
		"outer_a": []any{
			map[string]any{"k": "v", "j": "w"},
		},
	}
	got, err := CanonicalEventBytes(ev)
	if err != nil {
		t.Fatalf("CanonicalEventBytes: %v", err)
	}
	want := `{"outer_a":[{"j":"w","k":"v"}],"outer_b":{"a":2,"z":1}}`
	if string(got) != want {
		t.Errorf("nested canonical bytes = %s, want %s", got, want)
	}
}

func TestCanonicalEventBytes_NoHTMLEscape(t *testing.T) {
	ev := map[string]any{"rationale": "read & verify <stuff>"}
	got, err := CanonicalEventBytes(ev)
	if err != nil {
		t.Fatalf("CanonicalEventBytes: %v", err)
	}
	want := `{"rationale":"read & verify <stuff>"}`
	if string(got) != want {
		t.Errorf("got %s, want %s (HTML escape must be off)", got, want)
	}
}

func TestCanonicalEventBytes_NilEvent(t *testing.T) {
	_, err := CanonicalEventBytes(nil)
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("nil event err = %v, want ErrInvalidEvent", err)
	}
}

// ─── Envelope sign + verify round-trip ─────────────────────────────────────

func TestEnvelopeSign_VerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ev := map[string]any{
		"alpha": "first",
		"beta":  []any{"x", "y", "z"},
		"gamma": map[string]any{"k": "v"},
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigB64, ok := ev[EnvelopeSignatureField].(string)
	if !ok || sigB64 == "" {
		t.Fatalf("envelope_signature not inserted: %#v", ev[EnvelopeSignatureField])
	}
	if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
		t.Errorf("envelope_signature is not valid base64: %v", err)
	}
	if err := VerifyEnvelopeSignature(pub, ev); err != nil {
		t.Errorf("Verify: %v (sig should round-trip)", err)
	}
}

func TestEnvelopeVerify_MissingSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyEnvelopeSignature(pub, map[string]any{"a": 1}); !errors.Is(err, ErrEnvelopeSignatureMissing) {
		t.Errorf("missing sig err = %v, want ErrEnvelopeSignatureMissing", err)
	}
}

func TestEnvelopeVerify_TamperedAfterSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ev := map[string]any{"original": "value"}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Tamper with a non-signature field after signing.
	ev["original"] = "TAMPERED"
	if err := VerifyEnvelopeSignature(pub, ev); !errors.Is(err, ErrEnvelopeSignatureInvalid) {
		t.Errorf("tampered verify = %v, want ErrEnvelopeSignatureInvalid", err)
	}
}

func TestEnvelopeVerify_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	ev := map[string]any{"a": 1}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := VerifyEnvelopeSignature(otherPub, ev); !errors.Is(err, ErrEnvelopeSignatureInvalid) {
		t.Errorf("wrong-key verify = %v, want ErrEnvelopeSignatureInvalid", err)
	}
}

func TestEnvelopeVerify_NonBase64(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ev := map[string]any{"a": 1, EnvelopeSignatureField: "not!base64!!!"}
	if err := VerifyEnvelopeSignature(pub, ev); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("non-base64 sig err = %v, want ErrInvalidEvent", err)
	}
}

// ─── Event constructors ────────────────────────────────────────────────────

func TestBuildAdmitted_RoundTripFields(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	sigs := []SignatureRef{
		{Role: "author", IdentityID: "id:kamir@m3c", SignatureB64: "AAA=", PubKeyFingerprint: "sha256:abc"},
		{Role: "registry", IdentityID: "id:kamir@m3c", SignatureB64: "BBB=", PubKeyFingerprint: "sha256:abc"},
	}
	ev, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       "sha256:" + strings.Repeat("a", 64),
		Name:               "fetch-contract",
		Version:            "1.0.0",
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         ts,
		Signatures:         sigs,
	})
	if err != nil {
		t.Fatalf("BuildBundleAdmittedEvent: %v", err)
	}
	for _, k := range []string{
		"schema_version", "event_id", "occurred_at", "bundle_digest", "name",
		"version", "author_intent", "admitted_by_identity", "admitted_at",
		"blob_uri", "signatures", "tenant_scope",
	} {
		if _, ok := ev[k]; !ok {
			t.Errorf("missing required field %q", k)
		}
	}
	if ev["blob_uri"] != nil {
		t.Errorf("inline bundle should have blob_uri=null, got %v", ev["blob_uri"])
	}
	if ev["occurred_at"] != "2026-05-13T12:00:00Z" {
		t.Errorf("occurred_at = %v, want 2026-05-13T12:00:00Z", ev["occurred_at"])
	}
}

func TestBuildAdmitted_RejectsBadDigest(t *testing.T) {
	_, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       "sha256:NOT-LOWERCASE-HEX-AND-WRONG-LENGTH",
		Name:               "x",
		Version:            "1.0.0",
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         time.Now(),
		Signatures: []SignatureRef{
			{Role: "author"}, {Role: "registry"},
		},
	})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("bad digest err = %v, want ErrInvalidEvent", err)
	}
}

func TestBuildAdmitted_RejectsBadGovernance(t *testing.T) {
	_, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       "sha256:" + strings.Repeat("a", 64),
		Name:               "x",
		Version:            "1.0.0",
		AuthorIntent:       "purple",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         time.Now(),
		Signatures: []SignatureRef{
			{Role: "author"}, {Role: "registry"},
		},
	})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("bad governance err = %v, want ErrInvalidEvent", err)
	}
}

func TestBuildAdmitted_RequiresTwoSignatures(t *testing.T) {
	_, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       "sha256:" + strings.Repeat("a", 64),
		Name:               "x",
		Version:            "1.0.0",
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         time.Now(),
		Signatures:         []SignatureRef{{Role: "author"}},
	})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("one-sig err = %v, want ErrInvalidEvent", err)
	}
}

func TestBuildAttested_OK(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	ev, err := BuildAttestationPublishedEvent(AttestedEventInput{
		BundleDigest:    "sha256:" + strings.Repeat("a", 64),
		ReviewerID:      "id:kamir@m3c",
		GovernanceLevel: "green",
		Rationale:       "read-only",
		OccurredAt:      ts,
	})
	if err != nil {
		t.Fatalf("BuildAttestationPublishedEvent: %v", err)
	}
	if ev["governance_level"] != "green" {
		t.Errorf("governance_level = %v, want green", ev["governance_level"])
	}
	if ev["attestation_id"] == "" || ev["attestation_id"] == nil {
		t.Errorf("attestation_id should be auto-generated")
	}
}

func TestBuildRevoked_OK(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	ev, err := BuildBundleRevokedEvent(RevokedEventInput{
		BundleDigest: "sha256:" + strings.Repeat("a", 64),
		ReasonCode:   "deprecated",
		Rationale:    "superseded by v2",
		RevokedBy:    "id:kamir@m3c",
		OccurredAt:   ts,
	})
	if err != nil {
		t.Fatalf("BuildBundleRevokedEvent: %v", err)
	}
	if ev["revoked_at"] != "2026-05-13T12:00:00Z" {
		t.Errorf("revoked_at = %v", ev["revoked_at"])
	}
}

func TestBuildInstalled_OK(t *testing.T) {
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	ev, err := BuildBundleInstalledEvent(InstalledEventInput{
		BundleDigest:          "sha256:" + strings.Repeat("a", 64),
		Name:                  "fetch-contract",
		Version:               "1.0.0",
		InstalledOnHost:       "macbookpro-intel",
		InstalledAt:           ts,
		TrustRootsFingerprint: "sha256:fp",
		Registry:              "self",
	})
	if err != nil {
		t.Fatalf("BuildBundleInstalledEvent: %v", err)
	}
	if ev["installed_on_host"] != "macbookpro-intel" {
		t.Errorf("installed_on_host = %v", ev["installed_on_host"])
	}
	if ev["registry"] != "self" {
		t.Errorf("registry = %v", ev["registry"])
	}
}

// ─── End-to-end: build → sign → marshal → verify ────────────────────────────

func TestEndToEnd_BuildSignMarshalVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ts := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	ev, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       "sha256:" + strings.Repeat("a", 64),
		Name:               "fetch-contract",
		Version:            "1.0.0",
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         ts,
		Signatures: []SignatureRef{
			{Role: "author", IdentityID: "id:kamir@m3c"},
			{Role: "registry", IdentityID: "id:kamir@m3c"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Marshal as we'd put it in the ER1 item body, then read it back as a
	// generic map (mirrors what `pull` will do on the consumer side).
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(body, &roundTrip); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := VerifyEnvelopeSignature(pub, roundTrip); err != nil {
		t.Errorf("Verify after marshal+unmarshal: %v", err)
	}
}
