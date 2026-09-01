package main

// SPEC-0196 §12 Q1 / P2b — `skillctl pack --data-scopes` binds a typed,
// validated data-scope INTO the signed bundle.json. These tests drive runPack
// directly (no process spawn) and assert:
//
//   - a declared scope lands INSIDE bundle.json (so it is digest-covered → the
//     author signature covers it; the byte-level tamper proof lives in
//     pkg/skillbundle/datascope_binding_test.go),
//   - pack REJECTS a §3.3-contradictory scope fail-closed with exit 18 and the
//     SAME failed_rule the client/server `intent declare` validator emits,
//   - a malformed scope JSON is a usage error (exit 2), distinct from a
//     semantic rejection,
//   - packing WITHOUT --data-scopes leaves the manifest scope absent (unchanged
//     behavior — back-compat).

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// writePackSkillDir builds a minimal valid skill dir with a SKILL.md.
func writePackSkillDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: t\n---\n# t\n"), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	return dir
}

// readBundleJSON extracts and decodes bundle.json from a packed .skb.
func readBundleJSON(t *testing.T, skbPath string) skillbundle.BundleManifest {
	t.Helper()
	f, err := os.Open(skbPath)
	if err != nil {
		t.Fatalf("open skb: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if h.Name == "bundle.json" {
			raw, _ := io.ReadAll(tr)
			var m skillbundle.BundleManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("decode bundle.json: %v", err)
			}
			return m
		}
	}
	t.Fatalf("bundle.json not found in %s", skbPath)
	return skillbundle.BundleManifest{}
}

func baseArgs(skillDir, out string) []string {
	return []string{
		"--skill", skillDir,
		"-o", out,
		"--name", "t",
		"--version", "1.0.0",
		"--author-intent", "yellow",
	}
}

// TestPackDataScopeBoundIntoSignedManifest: a declared scope is present in the
// signed bundle.json with every field conserved.
func TestPackDataScopeBoundIntoSignedManifest(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "t@1.0.0.skb")
	var stdout, stderr bytes.Buffer

	scope := `{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/decks/**","reason":"write the scaffolded decks","payload_class":"config","retention":"persistent"}`
	args := append(baseArgs(dir, out),
		"--destructive", "true", // write access requires destructive=true (§3.3 rule 3)
		"--data-scopes", scope,
	)

	if code := runPack(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("runPack exit=%d, stderr=%s", code, stderr.String())
	}

	m := readBundleJSON(t, out)
	if len(m.DataDependencies) != 1 {
		t.Fatalf("want 1 data_dependency in signed manifest, got %d", len(m.DataDependencies))
	}
	d := m.DataDependencies[0]
	if d.ID != "ds:fs/cwd" || d.Kind != "local_fs" || d.Access != "write" ||
		d.Scope != "<cwd>/decks/**" || d.Reason != "write the scaffolded decks" ||
		d.PayloadClass != "config" || d.Retention != "persistent" {
		t.Fatalf("data_dependency fields not conserved into signed manifest: %+v", d)
	}
	if m.Intent == nil || !m.Intent.Destructive {
		t.Fatalf("intent.destructive not bound into signed manifest: %+v", m.Intent)
	}
	if !strings.Contains(stdout.String(), "author-signed") {
		t.Errorf("stdout should note author-signed binding, got: %s", stdout.String())
	}
}

// TestPackRejectsContradictoryScopeFailClosed: a write scope paired with
// intent.destructive=false fires §3.3 rule write_access_non_destructive →
// exit 18, the SAME failed_rule the intent-declare validator emits, and NO
// bundle is produced.
func TestPackRejectsContradictoryScopeFailClosed(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "bad.skb")
	var stdout, stderr bytes.Buffer

	scope := `{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/x/**","reason":"r"}`
	args := append(baseArgs(dir, out),
		"--destructive", "false", // contradiction: write access but not destructive
		"--data-scopes", scope,
	)

	code := runPack(args, &stdout, &stderr)
	if code != verify.ExitIntentInconsistent {
		t.Fatalf("want exit %d (intent_inconsistent), got %d; stderr=%s",
			verify.ExitIntentInconsistent, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed_rule=write_access_non_destructive") {
		t.Errorf("stderr should name the §3.3 rule, got: %s", stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("fail-closed violated: bundle was produced at %s despite invalid scope", out)
	}
}

// TestPackRejectsDestructiveGreen: destructive=true + green Ampel fires
// §3.3 rule destructive_green → exit 18.
func TestPackRejectsDestructiveGreen(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "bad.skb")
	var stdout, stderr bytes.Buffer

	args := []string{
		"--skill", dir, "-o", out, "--name", "t", "--version", "1.0.0",
		"--author-intent", "green",
		"--destructive", "true",
	}
	code := runPack(args, &stdout, &stderr)
	if code != verify.ExitIntentInconsistent {
		t.Fatalf("want exit %d, got %d; stderr=%s", verify.ExitIntentInconsistent, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed_rule=destructive_green") {
		t.Errorf("stderr should name destructive_green, got: %s", stderr.String())
	}
}

// TestPackRejectsMalformedScopeJSON: a non-JSON scope is a usage error (exit 2),
// NOT a semantic §3.3 rejection.
func TestPackRejectsMalformedScopeJSON(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "bad.skb")
	var stdout, stderr bytes.Buffer

	args := append(baseArgs(dir, out), "--data-scopes", "{not json")
	code := runPack(args, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("want exit %d (usage) for malformed JSON, got %d; stderr=%s", exitUsage, code, stderr.String())
	}
}

// TestPackRejectsStructurallyInvalidScope: a scope with an unknown kind is a
// structural failure → usage error (exit 2), distinct from a cross-rule.
func TestPackRejectsStructurallyInvalidScope(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "bad.skb")
	var stdout, stderr bytes.Buffer

	scope := `{"id":"ds:x","kind":"not_a_kind","access":"read","reason":"r"}`
	args := append(baseArgs(dir, out), "--data-scopes", scope)
	code := runPack(args, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("want exit %d (usage) for unknown kind, got %d; stderr=%s", exitUsage, code, stderr.String())
	}
}

// TestPackWithoutDataScopeUnchanged: omitting --data-scopes leaves the manifest
// scope absent — back-compat (a bundle packed the old way is unchanged).
func TestPackWithoutDataScopeUnchanged(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "t.skb")
	var stdout, stderr bytes.Buffer

	if code := runPack(baseArgs(dir, out), &stdout, &stderr); code != exitOK {
		t.Fatalf("runPack exit=%d, stderr=%s", code, stderr.String())
	}
	m := readBundleJSON(t, out)
	if len(m.DataDependencies) != 0 {
		t.Errorf("expected no data_dependencies when --data-scopes omitted, got %d", len(m.DataDependencies))
	}
	if m.Intent != nil {
		t.Errorf("expected nil intent when no intent flags set, got %+v", m.Intent)
	}
}

// TestPackDataDepAliasWarns: the deprecated --data-dep alias is accepted and
// behaves identically, with a one-line deprecation note.
func TestPackDataDepAliasWarns(t *testing.T) {
	dir := writePackSkillDir(t)
	out := filepath.Join(t.TempDir(), "t.skb")
	var stdout, stderr bytes.Buffer

	scope := `{"id":"ds:er1/x","kind":"er1_collection","access":"read","reason":"r"}`
	args := append(baseArgs(dir, out), "--data-dep", scope)
	if code := runPack(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("runPack exit=%d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--data-dep is deprecated") {
		t.Errorf("expected deprecation note for --data-dep, got: %s", stderr.String())
	}
	m := readBundleJSON(t, out)
	if len(m.DataDependencies) != 1 {
		t.Fatalf("want 1 data_dependency via alias, got %d", len(m.DataDependencies))
	}
}
