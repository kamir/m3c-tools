package signing

// SPEC-0196 P2b re-challenge finding #2 — the SIGN-BOUNDARY scope gate.
//
// Pack already refuses to produce bytes for an invalid declared scope. But
// SignBundle is a SECOND author-sign entrypoint: a hand-built .skb (assembled
// WITHOUT Pack) can carry a Pack-rejected, §3.3-contradictory scope and still
// reach the signer. The author signature covers manifest.Intent +
// manifest.DataDependencies, so SignBundle MUST refuse such a bundle — otherwise
// "no unvalidated scope is ever author-signed" does not hold at every sign
// boundary. These tests drive the real SignBundle with hand-built archives that
// bypass Pack.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/datascope"
)

// makeBundleWithManifest hand-builds a .skb (gzip tar) carrying a SKILL.md plus a
// bundle.json marshaled from m — deliberately NOT via skillbundle.Pack, so a
// scope Pack would reject can still be assembled and handed to the signer.
func makeBundleWithManifest(t *testing.T, dir, name string, m skillbundle.BundleManifest) string {
	t.Helper()

	manifestBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)

	write := func(rel string, body []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	write("SKILL.md", []byte("---\nname: t\n---\n# t\n"))
	write("bundle.json", manifestBytes)

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSignBundle_RefusesContradictoryScope is the finding #2 proof: a hand-built
// .skb whose manifest carries a §3.3-contradictory scope (destructive=true with
// author_governance_intent="green", Rule 1) must be REFUSED by SignBundle, and NO
// signature file may be written.
func TestSignBundle_RefusesContradictoryScope(t *testing.T) {
	dir := t.TempDir()
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	// Rule 1 violation: a destructive skill cannot be governance-green.
	m := skillbundle.BundleManifest{
		Name:                   "evil",
		Version:                "1.0.0",
		AuthorGovernanceIntent: "green",
		Intent:                 &skillbundle.Intent{Destructive: true, SideEffects: []string{"fs:write"}},
		DataDependencies: []skillbundle.DataDependency{
			{ID: "ds:fs/cwd", Kind: "local_fs", Access: "write", Scope: "<cwd>/**", Reason: "writes"},
		},
	}
	bundle := makeBundleWithManifest(t, dir, "evil.skb", m)

	_, _, err := SignBundle(bundle, keyOut+".priv", "id:test@m3c")
	if err == nil {
		t.Fatal("SignBundle author-signed a contradictory scope; want fail-closed refusal")
	}

	// The error must carry the structured validation failure so callers can map it.
	var ve *datascope.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error should wrap *datascope.ValidationError, got: %v", err)
	}
	if ve.FailedRule != datascope.RuleDestructiveGreen {
		t.Errorf("failed_rule = %q, want %q", ve.FailedRule, datascope.RuleDestructiveGreen)
	}

	// NO signature file may have been written (fail-closed).
	matches, _ := filepath.Glob(filepath.Join(dir, "*.author.sig"))
	if len(matches) != 0 {
		t.Errorf("a signature file was written despite the refusal: %v", matches)
	}
}

// TestSignBundle_AcceptsValidScope: the gate is a guard, not a wall — a hand-built
// .skb whose manifest carries a CONSISTENT scope still signs (proves the gate does
// not reject everything with a scope).
func TestSignBundle_AcceptsValidScope(t *testing.T) {
	dir := t.TempDir()
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	m := skillbundle.BundleManifest{
		Name:                   "ok",
		Version:                "1.0.0",
		AuthorGovernanceIntent: "yellow", // destructive ⇒ NOT green: consistent
		Intent:                 &skillbundle.Intent{Destructive: true, SideEffects: []string{"fs:write"}},
		DataDependencies: []skillbundle.DataDependency{
			{ID: "ds:fs/cwd", Kind: "local_fs", Access: "write", Scope: "<cwd>/decks/**", Reason: "writes decks"},
		},
	}
	bundle := makeBundleWithManifest(t, dir, "ok.skb", m)

	sigPath, _, err := SignBundle(bundle, keyOut+".priv", "id:test@m3c")
	if err != nil {
		t.Fatalf("SignBundle refused a VALID scope: %v", err)
	}
	if _, err := os.Stat(sigPath); err != nil {
		t.Errorf("expected a signature file at %s: %v", sigPath, err)
	}
}

// TestSignBundle_NoScopeStillSigns: a legacy .skb whose manifest declares no
// intent and no data dependencies has nothing to validate and signs exactly as
// before (no regression for pre-P2b bundles).
func TestSignBundle_NoScopeStillSigns(t *testing.T) {
	dir := t.TempDir()
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	m := skillbundle.BundleManifest{Name: "legacy", Version: "1.0.0"}
	bundle := makeBundleWithManifest(t, dir, "legacy.skb", m)

	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err != nil {
		t.Fatalf("SignBundle refused a no-scope legacy bundle: %v", err)
	}
}
