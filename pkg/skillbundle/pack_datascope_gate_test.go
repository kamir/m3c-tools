package skillbundle

// SPEC-0196 §12 Q1 / P2b — LIBRARY-BOUNDARY scope gate (challenge-gate finding #2).
//
// The author signature covers manifest.Intent + manifest.DataDependencies, so the
// validation gate MUST live at the pack/sign boundary itself — not only in the CLI.
// A programmatic producer that calls skillbundle.Pack directly (e.g.
// publish_cmds.go ensureBundle) must be bound by the SAME datascope.Validate rule.
// These tests prove Pack fails CLOSED on an invalid/contradictory scope and writes
// NO bundle.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/datascope"
)

// TestPack_RejectsInvalidScope_NoBundleWritten: an unbounded local_fs WRITE scope
// (no path glob) is invalid; Pack must return an error and write no file.
func TestPack_RejectsInvalidScope_NoBundleWritten(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "should-not-exist.skb")

	m := fixtureManifest()
	m.AuthorGovernanceIntent = "yellow"
	m.Intent = &Intent{SideEffects: []string{"fs:write"}, Destructive: true}
	m.DataDependencies = []DataDependency{
		// local_fs WRITE with NO scope → unbounded write, rejected by datascope.
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "write", Reason: "write somewhere"},
	}

	digest, err := Pack(src, out, PackOptions{Manifest: m, BuiltAt: fixedTime, BuiltBy: "skillctl/test"})
	if err == nil {
		t.Fatal("Pack must reject an unbounded local_fs write scope")
	}
	if digest != "" {
		t.Errorf("Pack returned a digest %q on rejection; want empty", digest)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("Pack wrote a bundle despite an invalid scope (stat err=%v)", statErr)
	}
}

// TestPack_RejectsContradictoryCrossRule_Exit18Mappable: a §3.3 cross-rule
// violation (write access but destructive=false) is rejected at the library
// boundary, and the error carries the stable FailedRule so the CLI can map it to
// exit 18 exactly as before.
func TestPack_RejectsContradictoryCrossRule_Exit18Mappable(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "should-not-exist.skb")

	m := fixtureManifest()
	m.AuthorGovernanceIntent = "yellow"
	dFalse := false
	m.Intent = &Intent{SideEffects: []string{"fs:write"}, Destructive: dFalse}
	m.DataDependencies = []DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "write", Scope: "<cwd>/decks/**", Reason: "write decks"},
	}

	_, err := Pack(src, out, PackOptions{Manifest: m, BuiltAt: fixedTime, BuiltBy: "skillctl/test"})
	if err == nil {
		t.Fatal("Pack must reject write-access with destructive=false (§3.3)")
	}
	var ve *datascope.ValidationError
	if !errors.As(err, &ve) || ve.FailedRule != datascope.RuleWriteAccessNonDestr {
		t.Errorf("Pack error must carry FailedRule=%q (got err=%v)", datascope.RuleWriteAccessNonDestr, err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("Pack wrote a bundle despite a cross-rule violation (stat err=%v)", statErr)
	}
}

// TestPack_AcceptsValidScope: the consistent scope from scopedManifest still packs
// successfully — the gate is fail-closed, not break-everything.
func TestPack_AcceptsValidScope(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "ok.skb")
	if _, err := Pack(src, out, PackOptions{Manifest: scopedManifest(), BuiltAt: fixedTime, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("Pack must accept a valid scope: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("Pack should have written the bundle: %v", statErr)
	}
}

// TestPack_NoScopeUnchanged: a manifest with neither intent nor data deps packs
// exactly as before (back-compat — the gate is a no-op when there is nothing to
// validate).
func TestPack_NoScopeUnchanged(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "plain.skb")
	m := fixtureManifest() // no Intent, no DataDependencies
	if _, err := Pack(src, out, PackOptions{Manifest: m, BuiltAt: fixedTime, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("Pack must accept a scope-free manifest: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("Pack should have written the bundle: %v", statErr)
	}
}
