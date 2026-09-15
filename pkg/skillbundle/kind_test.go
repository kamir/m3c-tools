package skillbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bundle kind (SPEC-0432 §3.2). The load-bearing property is NEGATIVE: a
// skill must emit exactly the bytes it emitted before the Kind field existed,
// because pack.go re-serializes the manifest from the struct and hashes the
// result. TestDigestStability in pack_test.go is the guard for that, pinned
// against goldenDigest; the tests here cover the mechanism behind it.

// TestSkillManifestOmitsKind: a skill writes NO kind key at all, and stays on
// schema v1. This is why goldenDigest survives the new field.
func TestSkillManifestOmitsKind(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "skill.skb")
	if _, err := Pack(src, out, PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	raw := readTarFile(t, out, "bundle.json")

	// Decode into a map, not into BundleManifest: a struct cannot tell "absent"
	// from "empty", and absent is the whole point. A raw byte scan for `"kind"`
	// does NOT work either, because every depends_on[] entry carries its own
	// `kind` ("python", "system", "skill"). Only the TOP-LEVEL key matters here.
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m["kind"]; present {
		t.Fatalf("skill bundle.json must not carry a top-level kind key, got:\n%s", raw)
	}
	if got := m["schema"]; got != Schema {
		t.Fatalf("skill schema = %v, want %s", got, Schema)
	}
}

// TestAgentManifestCarriesKindAndSchemaV2: the agent side, SPEC-0432 AC-13.
func TestAgentManifestCarriesKindAndSchemaV2(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "agent.skb")
	man := fixtureManifest()
	man.Kind = KindAgent
	if _, err := Pack(src, out, PackOptions{Manifest: man, BuiltAt: fixedTime}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(readTarFile(t, out, "bundle.json"), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := m["kind"]; got != KindAgent {
		t.Fatalf("kind = %v, want %s", got, KindAgent)
	}
	if got := m["schema"]; got != SchemaAgent {
		t.Fatalf("agent schema = %v, want %s", got, SchemaAgent)
	}
}

// TestSkillAndAgentDigestsDiffer: the two kinds of the same source are not
// interchangeable. Without this an agent could be mistaken for its skill.
func TestSkillAndAgentDigestsDiffer(t *testing.T) {
	src := writeFixtureSkill(t)
	out := t.TempDir()

	skillDigest, err := Pack(src, filepath.Join(out, "s.skb"),
		PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime})
	if err != nil {
		t.Fatalf("pack skill: %v", err)
	}
	man := fixtureManifest()
	man.Kind = KindAgent
	agentDigest, err := Pack(src, filepath.Join(out, "a.skb"),
		PackOptions{Manifest: man, BuiltAt: fixedTime})
	if err != nil {
		t.Fatalf("pack agent: %v", err)
	}
	if skillDigest == agentDigest {
		t.Fatalf("skill and agent bundle share digest %s", skillDigest)
	}
}

// TestEffectiveKind: the ONE place that resolves an absent kind (SPEC-0432 §3.2).
func TestEffectiveKind(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", KindSkill}, // the 78 bundles admitted before SPEC-0432
		{KindSkill, KindSkill},
		{KindAgent, KindAgent},
	} {
		if got := (BundleManifest{Kind: tc.in}).EffectiveKind(); got != tc.want {
			t.Errorf("EffectiveKind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestValidKind pins the accepted set, case included. "Agent" is NOT accepted:
// the kind ends up in a signed manifest and in a registry key, so one spelling
// is the only spelling.
func TestValidKind(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{KindSkill, true},
		{KindAgent, true},
		{"Agent", false},
		{"SKILL", false},
		{"unsinn", false},
		{" agent", false},
	} {
		if got := ValidKind(tc.in); got != tc.want {
			t.Errorf("ValidKind(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestPackRejectsUnknownKind: fail closed, SPEC-0432 AC-12. The assertion on
// the absent file is the real one; an error return that still leaves a bundle
// behind would be worse than no check at all.
func TestPackRejectsUnknownKind(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "nope.skb")
	man := fixtureManifest()
	man.Kind = "unsinn"

	_, err := Pack(src, out, PackOptions{Manifest: man, BuiltAt: fixedTime})
	if err == nil {
		t.Fatal("pack accepted an unknown kind")
	}
	msg := err.Error()
	for _, want := range []string{`"unsinn"`, KindSkill, KindAgent, "no bundle written"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %q", msg, want)
		}
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("a bundle was written despite the error: %v", statErr)
	}
}
