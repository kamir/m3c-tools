package main

// SPEC-0275 — skill-bundled runbooks: pack inclusion, descriptor parsing, and
// the best-effort auto-register hook.

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// T2/T5 — the sidecar descriptor: required fields + version override (pure).
func TestParseRunbookDescriptor(t *testing.T) {
	// happy path: version overridden by the skill version
	d, err := parseRunbookDescriptor([]byte(`{"runbook_id":"rb-x","title":"X","version":"9.9.9"}`), "1.2.3")
	if err != nil {
		t.Fatalf("valid meta: %v", err)
	}
	if d["version"] != "1.2.3" {
		t.Fatalf("version must be overridden by skill version, got %v", d["version"])
	}
	if d["runbook_id"] != "rb-x" {
		t.Fatalf("runbook_id lost: %v", d["runbook_id"])
	}

	// missing runbook_id → error
	if _, err := parseRunbookDescriptor([]byte(`{"title":"X"}`), "1.0.0"); err == nil {
		t.Fatal("expected error for missing runbook_id")
	}
	// missing title → error
	if _, err := parseRunbookDescriptor([]byte(`{"runbook_id":"rb-x"}`), "1.0.0"); err == nil {
		t.Fatal("expected error for missing title")
	}
	// invalid JSON → error
	if _, err := parseRunbookDescriptor([]byte(`{not json`), "1.0.0"); err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

// T1 — pack includes runbook.html + runbook.meta.json (WalkDir packs the whole dir).
func TestPackIncludesRunbook(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("SKILL.md", "---\nname: demo\nversion: 0.1.0\n---\n")
	write("runbook.html", "<!doctype html><title>demo</title>")
	write("runbook.meta.json", `{"runbook_id":"rb-demo","title":"Demo"}`)

	out := filepath.Join(t.TempDir(), "demo@0.1.0.skb")
	if _, err := skillbundle.Pack(dir, out, skillbundle.PackOptions{}); err != nil {
		t.Fatalf("pack: %v", err)
	}

	names := tarEntryNames(t, out)
	for _, want := range []string{"runbook.html", "runbook.meta.json", "SKILL.md"} {
		if !names[want] {
			t.Errorf("packed .skb missing %q (entries: %v)", want, names)
		}
	}
}

// T4 + pairing — the auto-register hook is always best-effort: it never panics
// and never blocks the caller, whatever the catalog / filesystem state.
func TestMaybeRegisterRunbook_BestEffort(t *testing.T) {
	// flag off → immediate no-op even with files present
	t.Run("disabled", func(t *testing.T) {
		dir := skillDirWithRunbook(t)
		maybeRegisterRunbook(io_discard(), io_discard(), publishAdmitArgs{name: "demo", skillDir: dir, noRunbookPublish: true}, "0.1.0")
	})
	// no runbook files → silent no-op
	t.Run("no-runbook", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644)
		maybeRegisterRunbook(io_discard(), io_discard(), publishAdmitArgs{name: "demo", skillDir: dir}, "0.1.0")
	})
	// only one of the pair → skip (warn), no crash
	t.Run("orphan-html", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "runbook.html"), []byte("<html>"), 0o644)
		maybeRegisterRunbook(io_discard(), io_discard(), publishAdmitArgs{name: "demo", skillDir: dir}, "0.1.0")
	})
	// catalog returns 500 → warn, but the function returns normally (non-fatal)
	t.Run("catalog-5xx-non-fatal", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		t.Setenv("ER1_DEVICE_TOKEN", "test-token")
		dir := skillDirWithRunbook(t)
		// er1Endpoint passes through an http:// target verbatim.
		maybeRegisterRunbook(io_discard(), io_discard(), publishAdmitArgs{name: "demo", skillDir: dir, er1Target: srv.URL}, "0.1.0")
		// no assertion needed: a panic or os.Exit would fail the test; reaching here = non-fatal.
	})
}

func skillDirWithRunbook(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "runbook.html"), []byte("<!doctype html>"), 0o644)
	os.WriteFile(filepath.Join(dir, "runbook.meta.json"), []byte(`{"runbook_id":"rb-demo","title":"Demo"}`), 0o644)
	return dir
}

func tarEntryNames(t *testing.T, skb string) map[string]bool {
	t.Helper()
	f, err := os.Open(skb)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names[strings.TrimPrefix(hdr.Name, "./")] = true
	}
	return names
}

func io_discard() *os.File {
	// /dev/null sink for stdout/stderr in tests that only check non-fatality.
	f, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	return f
}
