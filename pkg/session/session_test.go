package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// pure construction
// ---------------------------------------------------------------------------

func TestSlugifyAndShortHost(t *testing.T) {
	if got := slugify("My Project!  "); got != "My-Project" {
		t.Fatalf("slugify = %q", got)
	}
	if got := slugify("///"); got != "unknown" {
		t.Fatalf("slugify(empty) = %q", got)
	}
	h := shortHost()
	if h == "" || strings.Contains(h, ".") {
		t.Fatalf("shortHost = %q (want non-empty, no dots)", h)
	}
}

func TestER1Endpoint(t *testing.T) {
	cases := []struct {
		in     string
		url    string
		verify bool
	}{
		{"prod", "https://onboarding.guide", true},
		{"", "https://onboarding.guide", true},
		{"local", "https://127.0.0.1:8081", false},
		{"http://127.0.0.1:5555", "http://127.0.0.1:5555", false},
		{"https://kup.onboarding.guide", "https://kup.onboarding.guide", true},
	}
	for _, c := range cases {
		u, v := ER1Endpoint(c.in)
		if u != c.url || v != c.verify {
			t.Errorf("ER1Endpoint(%q) = (%q, %v), want (%q, %v)", c.in, u, v, c.url, c.verify)
		}
	}
}

func TestSessionStateTagsAndBody(t *testing.T) {
	id := newIdentReal(t)
	tags := id.SessionStateTags("")
	want := map[string]bool{
		"claude-code.session": true, "session:" + id.SessionID: true,
		"project:" + id.Project: true, "cwd:" + id.CwdSlug: true,
		"host:" + id.Host: true, "claude-code.session.open": true,
	}
	got := map[string]bool{}
	for _, tg := range tags {
		got[tg] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("missing tag %q in %v", w, tags)
		}
	}
	if id.Device != "" {
		found := false
		for _, tg := range tags {
			if tg == "device:"+id.Device {
				found = true
			}
		}
		if !found {
			t.Errorf("device tag missing")
		}
	}
	// continues edge
	ct := id.SessionStateTags("main/abc123")
	hasContinues := false
	for _, tg := range ct {
		if tg == "link/continues/main/abc123" {
			hasContinues = true
		}
	}
	if !hasContinues {
		t.Errorf("link/continues tag missing: %v", ct)
	}

	body := id.SessionStateBody("ship R1.2", "", "skillctl")
	for _, sub := range []string{"spec: SPEC-0213", "kind: session-state",
		"session_id: " + id.SessionID, "project: " + id.Project,
		"er1_target: prod", "transcript_pointer: local-session://" + id.Host + "/" + id.SessionID,
		"## Intent\nship R1.2"} {
		if !strings.Contains(body, sub) {
			t.Errorf("body missing %q\n---\n%s", sub, body)
		}
	}
}

func TestCheckpointTags(t *testing.T) {
	id := newIdentReal(t)
	tags := id.CheckpointTags("ctx1", "sessdoc1", true, true)
	want := []string{
		"claude-code.checkpoint",
		"link/parent/ctx1/sessdoc1",
		"link/checkpoint/ctx1/sessdoc1",
		"session:" + id.SessionID,
		"claude-code.checkpoint.close",
		"auto:generated",
	}
	for _, w := range want {
		found := false
		for _, tg := range tags {
			if tg == w {
				found = true
			}
		}
		if !found {
			t.Errorf("checkpoint tags missing %q: %v", w, tags)
		}
	}
}

func TestScanSecrets(t *testing.T) {
	if len(scanSecrets("just normal text, project_id: kup-berlin-001")) != 0 {
		t.Error("false positive on benign text")
	}
	for _, bad := range []string{"ghp_0123456789abcdefghijklmnopqrstuvwxyz", "AKIAIOSFODNN7EXAMPLE", "-----BEGIN RSA PRIVATE KEY-----", "api_key: superLongSecretValue12345"} {
		if len(scanSecrets(bad)) == 0 {
			t.Errorf("missed secret-shaped: %q", bad)
		}
	}
}

// newIdentReal builds an Ident with a real (empty) m3cproject.Descriptor by
// resolving a temp dir — so CommitSHAFromGit()/RepoRoot are real method calls.
func newIdentReal(t *testing.T) *Ident {
	t.Helper()
	dir := t.TempDir()
	id, err := ResolveIdent(dir, "15dce534-3d0d-4b79-ba54-b6bc56f7aa86", "kup-berlin-001", "prod", "main")
	if err != nil {
		t.Fatalf("ResolveIdent: %v", err)
	}
	id.Host = "laptop-mkp"
	id.Device = "synology-nas-001"
	id.Branch, id.Head, id.Dirty, id.Ahead = "master", "83e1b31", true, 2
	return id
}

// ---------------------------------------------------------------------------
// Open — integration against an httptest ER1
// ---------------------------------------------------------------------------

func TestOpen_AgainstFakeER1(t *testing.T) {
	var gotUploadTags string
	var searchHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/memory/") && strings.Contains(r.URL.Path, "/search"):
			searchHits++
			// first call (idempotency check) → empty
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		case r.URL.Path == "/upload_2":
			_ = r.ParseMultipartForm(10 << 20)
			gotUploadTags = r.FormValue("tags")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"doc_id": "DOC_FAKE_1", "message": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// a repo dir with a .m3c/project.yaml pointing er1.target at the fake server
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".m3c"), 0o755); err != nil {
		t.Fatal(err)
	}
	desc := "schema: m3c.project-descriptor/v2\nspec: SPEC-0214\n" +
		"plm: {project_id: kup-berlin-001, name: KuP, client: K-U-P, status: active}\n" +
		"er1: {target: " + srv.URL + ", context: main}\n" +
		"source: {plm_doc_updated_at: 2026-05-12T08:00:00Z, generated_at: x, generated_by: x, commit_sha: null}\n"
	if err := os.WriteFile(filepath.Join(dir, ".m3c", "project.yaml"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ER1_API_KEY", "test-key-1234567890")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("M3C_DEVICES_DIR", filepath.Join(dir, "no-such")) // skip device lookup
	t.Setenv("CLAUDE_SESSION_ID", "")

	r, err := Open(OpenOpts{WorkingDir: dir, SessionID: "sess-abc-1", Intent: "test session"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if r.DocID != "DOC_FAKE_1" || r.AlreadyExists {
		t.Fatalf("Open result = %+v", r)
	}
	for _, want := range []string{"claude-code.session", "session:sess-abc-1", "project:kup-berlin-001", "claude-code.session.open"} {
		if !strings.Contains(gotUploadTags, want) {
			t.Errorf("upload tags %q missing %q", gotUploadTags, want)
		}
	}
	if searchHits == 0 {
		t.Errorf("expected an idempotency search call")
	}

	// idempotency: now make search return the existing doc → Open is a no-op
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/search") {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"doc_id": "DOC_EXISTING"}}})
			return
		}
		t.Errorf("unexpected request to %s when session already exists", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv2.Close()
	desc2 := strings.Replace(desc, srv.URL, srv2.URL, 1)
	_ = os.WriteFile(filepath.Join(dir, ".m3c", "project.yaml"), []byte(desc2), 0o644)
	r2, err := Open(OpenOpts{WorkingDir: dir, SessionID: "sess-abc-1"})
	if err != nil {
		t.Fatalf("Open (idempotent): %v", err)
	}
	if !r2.AlreadyExists || r2.DocID != "DOC_EXISTING" {
		t.Fatalf("expected idempotent no-op returning DOC_EXISTING, got %+v", r2)
	}
}
