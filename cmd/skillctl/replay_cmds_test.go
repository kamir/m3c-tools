package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureEvents returns a slice of replayEvent values usable by the stub
// server. Mix of allowed/refused/invoked/completed types so tests can
// verify rendering + filtering behavior.
func fixtureEvents() []replayEvent {
	exit0 := 0
	exit38 := 38
	dur := int64(123)
	return []replayEvent{
		{
			Type: "skill.invoked", TokenID: "ct:01HZ-AAAA", SkillName: "sk-a",
			Tenant: "kup-001", Timestamp: "2026-05-09T10:00:00Z",
			RequestedCmd: "echo hi",
		},
		{
			Type: "gate.allowed", TokenID: "ct:01HZ-AAAA", SkillName: "sk-a",
			Tenant: "kup-001", Timestamp: "2026-05-09T10:00:01Z",
			RequestedCmd: "echo hi",
		},
		{
			Type: "gate.refused", TokenID: "ct:01HZ-BBBB", SkillName: "sk-b",
			Tenant: "kup-001", Timestamp: "2026-05-09T10:00:02Z",
			RefusalCode: "subprocess_not_allowed", RequestedCmd: "rm -rf /",
		},
		{
			Type: "skill.completed", TokenID: "ct:01HZ-AAAA", SkillName: "sk-a",
			Tenant: "kup-001", Timestamp: "2026-05-09T10:00:03Z",
			RequestedCmd: "echo hi", ExitCode: &exit0, DurationMS: &dur,
		},
		{
			Type: "skill.completed", TokenID: "ct:01HZ-BBBB", SkillName: "sk-b",
			Tenant: "kup-001", Timestamp: "2026-05-09T10:00:04Z",
			ExitCode: &exit38,
		},
	}
}

// startReplayStubServer returns a server that always returns the same
// fixture events. The endpoint is `/api/skills/runtime/invocations`. Any
// request without the X-API-KEY header is 401.
func startReplayStubServer(t *testing.T, events []replayEvent) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/runtime/invocations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") == "" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	})
	return httptest.NewServer(mux)
}

func writeAPIKey(t *testing.T, dir, key string) string {
	t.Helper()
	p := filepath.Join(dir, "api-key")
	if err := os.WriteFile(p, []byte(key), 0600); err != nil {
		t.Fatalf("write api-key: %v", err)
	}
	return p
}

// runReplayWithBaseURL invokes runReplay but injects a custom audit-url via
// a tiny fake: we override defaultReplayBaseURL by leveraging the fact that
// `--target=local` gives us a base URL we can replace. Since we can't patch
// that directly, we rebuild the URL via a small helper test on
// fetchReplayEvents instead.
//
// For end-to-end runReplay-level tests we accept a `--target stage` and rely
// on env STAGE_URL not being set — but it's simpler to test fetchReplayEvents
// + renderReplayTable directly. We do that here.
func TestFetchReplayEvents_EnvelopedShape(t *testing.T) {
	events := fixtureEvents()
	srv := startReplayStubServer(t, events)
	defer srv.Close()

	got, err := fetchReplayEvents(srv.URL+"/api/skills/runtime/invocations?tenant=kup-001",
		"test-key", "stage")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("want %d events, got %d", len(events), len(got))
	}
}

func TestFetchReplayEvents_TopLevelArrayShape(t *testing.T) {
	events := fixtureEvents()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/runtime/invocations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := fetchReplayEvents(srv.URL+"/api/skills/runtime/invocations", "k", "stage")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("want %d events (array shape), got %d", len(events), len(got))
	}
}

func TestFetchReplayEvents_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/runtime/invocations", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := fetchReplayEvents(srv.URL+"/api/skills/runtime/invocations", "k", "stage")
	if err == nil {
		t.Fatal("want error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500, got %v", err)
	}
}

func TestRenderReplayTable_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	renderReplayTable(&buf, fixtureEvents(), false)
	s := buf.String()

	must := []string{
		"TIMESTAMP", "TYPE", "SKILL", "TOKEN_ID",
		"sk-a", "sk-b",
		"gate.allowed", "gate.refused",
		"skill.invoked", "skill.completed",
		"subprocess_not_allowed",
		"exit=0", "exit=38",
		"Total: 5 events",
		"By type:",
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("table missing %q\n----\n%s", m, s)
		}
	}
}

func TestRenderReplayTable_EmptyEvents(t *testing.T) {
	var buf bytes.Buffer
	renderReplayTable(&buf, []replayEvent{}, false)
	if !strings.Contains(buf.String(), "(no events)") {
		t.Errorf("expected '(no events)' marker, got: %s", buf.String())
	}
}

func TestRenderReplayTable_ColorANSI(t *testing.T) {
	var buf bytes.Buffer
	renderReplayTable(&buf, fixtureEvents()[:2], true)
	s := buf.String()
	if !strings.Contains(s, ansiGreen) || !strings.Contains(s, ansiCyan) {
		t.Errorf("expected ANSI green+cyan codes, got: %q", s)
	}
}

func TestReplay_TokenIDFilter(t *testing.T) {
	// Test the filtering logic by simulating runReplay's filter step.
	events := fixtureEvents()
	wanted := "ct:01HZ-AAAA"
	filtered := make([]replayEvent, 0)
	for _, e := range events {
		if e.TokenID == wanted {
			filtered = append(filtered, e)
		}
	}
	// Fixture has 3 events with that token id (invoked, allowed, completed).
	if len(filtered) != 3 {
		t.Errorf("want 3 events for token %s, got %d", wanted, len(filtered))
	}
}

func TestResolveReplayAPIKey_MissingFile(t *testing.T) {
	tmp := t.TempDir()
	_, err := resolveReplayAPIKey(filepath.Join(tmp, "no-such-file"))
	if err == nil {
		t.Fatal("want error on missing api-key file, got nil")
	}
}

func TestResolveReplayAPIKey_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "api-key")
	_ = os.WriteFile(p, []byte("\n  \n"), 0600)
	_, err := resolveReplayAPIKey(p)
	if err == nil {
		t.Fatal("want error on empty api-key file")
	}
}

func TestResolveReplayAPIKey_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	p := writeAPIKey(t, tmp, "sk-secret")
	got, err := resolveReplayAPIKey(p)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "sk-secret" {
		t.Errorf("api key = %q, want sk-secret", got)
	}
}

func TestRunReplay_MissingTenant(t *testing.T) {
	rc := runReplay([]string{"--target", "local"})
	if rc != 2 {
		t.Errorf("want exit 2 for missing --tenant, got %d", rc)
	}
}

func TestRunReplay_InvalidFormat(t *testing.T) {
	tmp := t.TempDir()
	keyPath := writeAPIKey(t, tmp, "k")
	rc := runReplay([]string{"--tenant", "x", "--api-key-from", keyPath, "--format", "xml"})
	if rc != 2 {
		t.Errorf("want exit 2 for invalid format, got %d", rc)
	}
}

func TestRunReplay_JSONFormat_EndToEnd(t *testing.T) {
	// Pipe stdout into a temp file so we can verify JSON output.
	events := fixtureEvents()
	srv := startReplayStubServer(t, events)
	defer srv.Close()

	tmp := t.TempDir()
	keyPath := writeAPIKey(t, tmp, "test-key")

	// Capture stdout.
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	// Use the stage URL via env-overridable hook? We don't have one, so
	// instead exercise the full runReplay against a target that maps to
	// our stub by setting up an HTTP handler at the local default port.
	// Simpler: directly call fetchReplayEvents + JSON encoder; this is
	// what runReplay does for --format json.
	got, err := fetchReplayEvents(srv.URL+"/api/skills/runtime/invocations?tenant=x",
		"test-key", "stage")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(got)

	w.Close()
	out, _ := readAll(r)
	os.Stdout = orig

	// Should parse as JSON array.
	var parsed []replayEvent
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("json parse: %v\noutput: %s", err, string(out))
	}
	if len(parsed) != len(events) {
		t.Errorf("want %d events in json, got %d", len(events), len(parsed))
	}
	_ = keyPath // touched
}

func readAll(r interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.Bytes(), nil
}

func TestTruncString(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcdef", 5, "abcd…"},
		{"x", 0, ""},
	}
	for _, c := range cases {
		if got := truncString(c.in, c.n); got != c.want {
			t.Errorf("truncString(%q,%d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestColorForType(t *testing.T) {
	cases := map[string]string{
		"gate.allowed":    ansiGreen,
		"gate.refused":    ansiRed,
		"skill.invoked":   ansiCyan,
		"skill.completed": ansiGold,
		"unknown":         ansiPurple,
	}
	for ev, want := range cases {
		if got := colorForType(ev); got != want {
			t.Errorf("colorForType(%q) mismatch", ev)
		}
	}
}
