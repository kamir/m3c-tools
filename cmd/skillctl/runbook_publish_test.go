package main

// SPEC-0275, skill-bundled runbooks: pack inclusion, descriptor parsing, and
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

// T2/T5, the sidecar descriptor: required fields + version override (pure).
func TestParseRunbookDescriptor(t *testing.T) {
	// happy path: version overridden by the skill version
	d, _, err := parseRunbookDescriptor([]byte(`{"runbook_id":"rb-x","title":"X","version":"9.9.9"}`), "1.2.3")
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
	if _, _, err := parseRunbookDescriptor([]byte(`{"title":"X"}`), "1.0.0"); err == nil {
		t.Fatal("expected error for missing runbook_id")
	}
	// missing title → error
	if _, _, err := parseRunbookDescriptor([]byte(`{"runbook_id":"rb-x"}`), "1.0.0"); err == nil {
		t.Fatal("expected error for missing title")
	}
	// invalid JSON → error
	if _, _, err := parseRunbookDescriptor([]byte(`{not json`), "1.0.0"); err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

// T6 (BUG-0224): a descriptor without steps stays VALID and publishable, and stops
// being silent about it. Silence was the bug: four of the five catalog entries were
// step-less, and nothing at publish time said they could never be worked.
//
// Top-level function, not a subtest of TestParseRunbookDescriptor: the acceptance
// criterion greps for the line "--- PASS: TestParseRunbookDescriptor_WarnsWithoutSteps".
func TestParseRunbookDescriptor_WarnsWithoutSteps(t *testing.T) {
	warnsFor := func(body string) []string {
		t.Helper()
		d, w, err := parseRunbookDescriptor([]byte(body), "1.0.0")
		if err != nil {
			t.Fatalf("a step-less descriptor is a legal catalog entry, want no error, got: %v", err)
		}
		if d["version"] != "1.0.0" {
			t.Fatalf("version override lost: %v", d["version"])
		}
		return w
	}

	// The BUG-0224 case: no steps at all.
	w := warnsFor(`{"runbook_id":"rb-x","title":"X"}`)
	if len(w) != 1 {
		t.Fatalf("missing steps: want exactly 1 warning, got %d: %v", len(w), w)
	}
	if !strings.Contains(w[0], "steps") {
		t.Errorf("the warning must name the missing field, got %q", w[0])
	}

	// An empty list is the same defect written differently.
	if w := warnsFor(`{"runbook_id":"rb-x","title":"X","steps":[]}`); len(w) != 1 {
		t.Errorf("empty steps: want exactly 1 warning, got %d: %v", len(w), w)
	}

	// required_step_ids drops a step without an id, so the entry is short a step
	// without anything failing. Warn instead.
	if w := warnsFor(`{"runbook_id":"rb-x","title":"X","steps":[{"title":"no id"}]}`); len(w) != 1 {
		t.Errorf("step without id: want exactly 1 warning, got %d: %v", len(w), w)
	}

	// validate_runbook_descriptor rejects duplicates server-side; catch them here.
	if w := warnsFor(`{"runbook_id":"rb-x","title":"X","steps":[{"id":"s1"},{"id":"s1"}]}`); len(w) != 1 {
		t.Errorf("duplicate step id: want exactly 1 warning, got %d: %v", len(w), w)
	}

	// An executable runbook warns about nothing. Without this case the test would
	// pass on a function that warns unconditionally.
	if w := warnsFor(`{"runbook_id":"rb-x","title":"X","steps":[{"id":"s1","required":true},{"id":"s2","required":false}]}`); len(w) != 0 {
		t.Errorf("descriptor with steps must not warn, got %v", w)
	}
}

// T1: pack includes runbook.html + runbook.meta.json (WalkDir packs the whole dir).
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

// T4 + pairing: the auto-register hook is always best-effort: it never panics
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
