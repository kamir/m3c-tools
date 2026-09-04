package git

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// TestGitEventsSignedIdentity is the FR-0090 IS-T1 regression: a genuinely signed
// revoke of digest X is committed at events/<Yhex>/0001-installed.json: the
// FILENAME lies ("installed") and the DIRECTORY lies (Y). Events() must derive the
// event identity from the SIGNED envelope: Kind = revoke, Digest = X. Against the
// old code it would report {install, sha256:Y} (filename + dirname projections), so
// a revoked/key-compromised bundle would slip through the pull gauntlet and the
// revoke would be redirected onto the innocent digest Y.
func TestGitEventsSignedIdentity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	bare := bareRepo(t)

	// A signed-SHAPED revoke of X. (The git backend's Events() surfaces the raw
	// envelope for the §7 verifier to re-check later; it does not itself verify the
	// signature, so the classification/anchor extraction is what IS-T1 pins.)
	xHex := strings.Repeat("a", 64)
	yHex := strings.Repeat("b", 64)
	xDigest := "sha256:" + xHex

	revEnv := map[string]any{
		"schema_version":     "1.0.0",
		"event_id":           "r-1",
		"occurred_at":        "2026-01-01T00:00:00Z",
		"bundle_digest":      xDigest, // the SIGNED anchor → the real target
		"revoked_by":         "id:gov@org",
		"reason_code":        "key-compromise",
		"envelope_signature": "aGVsbG8=", // irrelevant to Events() derivation
	}
	data, err := json.MarshalIndent(revEnv, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	// Seed the mislabeled event into the bare repo via a working clone: place the
	// revoke-of-X under events/<Yhex>/ with a "-installed.json" name.
	work := t.TempDir()
	mustGit(t, "", "clone", "--quiet", bare, work)
	mustGit(t, work, "checkout", "-B", "main")
	evDir := filepath.Join(work, "events", yHex)
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evDir, "0001-installed.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, work, "add", "-A")
	mustGit(t, work, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "seed mislabeled event")
	mustGit(t, work, "push", "origin", "main")

	b := newGitBackend(bare, "local")
	defer b.Close()

	ep, err := b.Events(context.Background(), artifact.ListFilter{}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(ep.Events) != 1 {
		t.Fatalf("Events returned %d records, want 1: %+v", len(ep.Events), ep.Events)
	}
	got := ep.Events[0]
	if got.Kind != artifact.KindRevoke {
		t.Errorf("Kind = %q, want %q (from the SIGNED revoked_by, NOT the -installed.json filename)", got.Kind, artifact.KindRevoke)
	}
	if got.Digest != xDigest {
		t.Errorf("Digest = %q, want %q (from the SIGNED bundle_digest X, NOT the events/<Yhex> dirname)", got.Digest, xDigest)
	}
	if got.NativeID != "0001-installed.json" {
		t.Errorf("NativeID = %q, want the advisory filename 0001-installed.json", got.NativeID)
	}
}

// TestGitEventsDropsAnchorlessEnvelope: an envelope with no signed discriminator
// (or no well-formed bundle_digest) is DROPPED. It can never influence a verdict.
func TestGitEventsDropsAnchorlessEnvelope(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	bare := bareRepo(t)
	yHex := strings.Repeat("c", 64)

	// No discriminator field and a junk digest → unclassifiable + invalid anchor.
	junk := map[string]any{"schema_version": "1.0.0", "bundle_digest": "not-a-digest", "note": "hi"}
	data, _ := json.MarshalIndent(junk, "", "  ")

	work := t.TempDir()
	mustGit(t, "", "clone", "--quiet", bare, work)
	mustGit(t, work, "checkout", "-B", "main")
	evDir := filepath.Join(work, "events", yHex)
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evDir, "0001-revoked.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, work, "add", "-A")
	mustGit(t, work, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "seed junk event")
	mustGit(t, work, "push", "origin", "main")

	b := newGitBackend(bare, "local")
	defer b.Close()
	ep, err := b.Events(context.Background(), artifact.ListFilter{}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(ep.Events) != 0 {
		t.Errorf("anchor-less/unclassifiable envelope must be dropped; got %d records: %+v", len(ep.Events), ep.Events)
	}
}
