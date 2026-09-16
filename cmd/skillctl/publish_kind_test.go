package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// publish --kind agent (SPEC-0432 T-02). These drive ensureBundle directly:
// the packing half is what T-02 owns, the registry half belongs to T-03.
// ensureBundle writes to ./<name>@<version>.skb, so every test chdirs into a
// temp dir first and never litters the repo.

func writeAgentDef(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name+".md")
	body := "---\nname: " + name + "\ndescription: fixture\n---\n\nDo the thing.\n"
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write agent def: %v", err)
	}
	return p
}

func archiveNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip %s: %v", path, err)
	}
	var out []string
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar %s: %v", path, err)
		}
		out = append(out, h.Name)
	}
	return out
}

func bundleManifestOf(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip %s: %v", path, err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar %s: %v", path, err)
		}
		if h.Name != "bundle.json" {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read bundle.json: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal bundle.json: %v", err)
		}
		return m
	}
	t.Fatalf("%s carries no bundle.json", path)
	return nil
}

// TestEnsureBundleAgent: the happy path. AC-1 (bundle half) and AC-14.
func TestEnsureBundleAgent(t *testing.T) {
	src := t.TempDir()
	writeAgentDef(t, src, "release-agent")
	t.Chdir(t.TempDir())

	out, ver, err := ensureBundle(publishAdmitArgs{
		name:      "release-agent",
		version:   "1.0.0",
		kind:      skillbundle.KindAgent,
		agentFile: filepath.Join(src, "release-agent.md"),
	}, io.Discard)
	if err != nil {
		t.Fatalf("ensureBundle: %v", err)
	}
	if ver != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", ver)
	}

	m := bundleManifestOf(t, out)
	if m["kind"] != skillbundle.KindAgent {
		t.Errorf("kind = %v, want %s", m["kind"], skillbundle.KindAgent)
	}
	if m["schema"] != skillbundle.SchemaAgent {
		t.Errorf("schema = %v, want %s", m["schema"], skillbundle.SchemaAgent)
	}

	var content []string
	for _, n := range archiveNames(t, out) {
		if n != "bundle.json" && n != "CHECKSUMS" {
			content = append(content, n)
		}
	}
	if len(content) != 1 || content[0] != "release-agent.md" {
		t.Fatalf("archive content = %v, want exactly [release-agent.md]", content)
	}
}

// TestEnsureBundleAgentMissingFile: the broken state a person actually hits.
// The message must name the path it looked at, and nothing may be written.
func TestEnsureBundleAgentMissingFile(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	missing := filepath.Join(t.TempDir(), "nope.md")

	_, _, err := ensureBundle(publishAdmitArgs{
		name: "nope", version: "1.0.0",
		kind: skillbundle.KindAgent, agentFile: missing,
	}, io.Discard)
	if err == nil {
		t.Fatal("ensureBundle accepted a missing agent file")
	}
	for _, want := range []string{missing, "--agent-file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Fatalf("something was written despite the error: %v", entries)
	}
}

// TestEnsureBundleRejectsUnknownKind: the check runs BEFORE any file work, so
// a typo cannot half-produce a bundle.
func TestEnsureBundleRejectsUnknownKind(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)

	_, _, err := ensureBundle(publishAdmitArgs{
		name: "whatever", version: "1.0.0", kind: "Agent",
	}, io.Discard)
	if err == nil {
		t.Fatal("ensureBundle accepted kind \"Agent\"")
	}
	if !strings.Contains(err.Error(), "no bundle written") {
		t.Errorf("error %q does not say the bundle was not written", err)
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Fatalf("something was written despite the error: %v", entries)
	}
}

// TestEnsureBundleSkillUnchanged: the guard on the other half. A skill packed
// through the new code path carries no kind and stays on schema v1.
func TestEnsureBundleSkillUnchanged(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# s\n"), 0644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	t.Chdir(t.TempDir())

	out, _, err := ensureBundle(publishAdmitArgs{
		name: "some-skill", version: "2.0.0", skillDir: src,
	}, io.Discard)
	if err != nil {
		t.Fatalf("ensureBundle: %v", err)
	}
	m := bundleManifestOf(t, out)
	if _, present := m["kind"]; present {
		t.Errorf("skill bundle carries a kind key: %v", m["kind"])
	}
	if m["schema"] != skillbundle.Schema {
		t.Errorf("schema = %v, want %s", m["schema"], skillbundle.Schema)
	}
}
