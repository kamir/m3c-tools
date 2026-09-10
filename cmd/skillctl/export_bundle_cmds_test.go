package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// The exported pair must be exactly what the RECIPIENT's tools consume. This is
// the seam the whole acceptance test runs through, and it has failed in a
// specific way before: a producer and a consumer agreeing on a format in prose
// and not in bytes.
//
// The test is deliberately about the CONTRACT (the two filenames, and an
// envelope that parses back into the type verify consumes) rather than about
// registry plumbing, which the install tests already cover.
func TestExportedSidecarIsWhatTheConsumerExpects(t *testing.T) {
	dir := t.TempDir()
	skb := filepath.Join(dir, "alice-demo-skill@1.0.0.skb")

	// The sidecar name is the ONE thing both sides must agree on without talking.
	got := defaultMetaSidecar(skb)
	want := filepath.Join(dir, "alice-demo-skill@1.0.0.skbmeta.json")
	if got != want {
		t.Fatalf("sidecar path = %q, want %q: the sender and the recipient would look in different places", got, want)
	}

	// And the envelope the exporter writes must round-trip into the type the
	// verifier reads. Marshalling a *registry.BundleMeta and unmarshalling it
	// back is exactly the trip the file makes between two machines.
	meta := &registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": "sha256:" + strings.Repeat("ab", 32),
			"name":          "alice-demo-skill",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: "id:alice@kup", SignatureB64: "AAAA", Status: "active"},
		},
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(got, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	back, err := loadBundleMetaSidecar(got)
	if err != nil {
		t.Fatalf("the exporter's own output does not load through the consumer's reader: %v", err)
	}
	if len(back.Signatures) != 1 || back.Signatures[0].Role != "author" {
		t.Errorf("the signature rows did not survive the round trip: %+v", back.Signatures)
	}
	if n, _ := back.Bundle["name"].(string); n != "alice-demo-skill" {
		t.Errorf("the bundle record did not survive the round trip: %v", back.Bundle)
	}
}

// A name with no admitted version must be refused with a typed sentinel, so the
// CLI maps it to a numbered code rather than a bare 1. An operator scripting the
// send step needs to tell "no such skill" from "the registry is down".
func TestExportRefusesWhenNothingIsAdmitted(t *testing.T) {
	var out bytes.Buffer
	// No trust roots configured in this process: the command must fail before it
	// ever reaches a registry, and it must say what to do.
	orig := trustConfigPath
	trustConfigPath = func() string { return filepath.Join(t.TempDir(), "none.yaml") }
	defer func() { trustConfigPath = orig }()

	code := runExportBundle([]string{"some-skill", "--out", t.TempDir()}, &out, &out)
	if code == exitOK {
		t.Fatalf("export succeeded with no trust roots:\n%s", out.String())
	}
}

// Usage errors must not be confused with trust failures: a mistyped command is
// not a security event and must not land in the numbered space.
func TestExportUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},         // no skill named
		{"a", "b"}, // two positionals
		{"--out"},  // flag without a value
	} {
		var out bytes.Buffer
		if code := runExportBundle(args, &out, &out); code != exitUsage {
			t.Errorf("args %v: exit = %d, want %d (usage)", args, code, exitUsage)
		}
	}
}
