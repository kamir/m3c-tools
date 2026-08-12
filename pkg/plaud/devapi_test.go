package plaud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderDataContent(t *testing.T) {
	t.Run("transcript segments with speakers", func(t *testing.T) {
		// A source_list item whose data_content is a JSON array of segments.
		seg := `[{"start_time":720,"content":"Hallo zusammen.","speaker":"Speaker 1"},{"start_time":2200,"content":"Ja genau.","speaker":"Speaker 2"}]`
		item, _ := json.Marshal(map[string]string{"data_content": seg})
		got := (&DevDetail{SourceList: []json.RawMessage{item}}).TranscriptText()
		want := "Speaker 1: Hallo zusammen. \nSpeaker 2: Ja genau."
		if got != want {
			t.Errorf("transcript = %q, want %q", got, want)
		}
	})
	t.Run("notes markdown passthrough", func(t *testing.T) {
		item, _ := json.Marshal(map[string]string{"data_content": "## Notes\n- point"})
		got := (&DevDetail{NoteList: []json.RawMessage{item}}).NotesText()
		if got != "## Notes\n- point" {
			t.Errorf("notes = %q", got)
		}
	})
	t.Run("fallback to direct text field", func(t *testing.T) {
		got := renderDataContent([]json.RawMessage{json.RawMessage(`{"text":"plain"}`)}, true)
		if got != "plain" {
			t.Errorf("fallback = %q, want plain", got)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if renderDataContent(nil, true) != "" {
			t.Error("empty list should yield empty string")
		}
	})
}

func TestNewDevClientFromFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	future := time.Now().Add(20 * time.Hour).UnixMilli()
	pastMs := time.Now().Add(-1 * time.Hour).UnixMilli()

	t.Run("valid, unexpired", func(t *testing.T) {
		p := write("ok.json", fmt.Sprintf(`{"access_token":"eyJ.a.b","refresh_token":"r","token_type":"bearer","expires_at":%d}`, future))
		c, err := NewDevClientFromFile(p)
		if err != nil || c.token != "eyJ.a.b" {
			t.Fatalf("got token=%q err=%v", c.token, err)
		}
	})
	t.Run("expired → error", func(t *testing.T) {
		p := write("exp.json", fmt.Sprintf(`{"access_token":"eyJ.a.b","expires_at":%d}`, pastMs))
		if _, err := NewDevClientFromFile(p); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("expected expired error, got %v", err)
		}
	})
	t.Run("missing file → actionable error", func(t *testing.T) {
		if _, err := NewDevClientFromFile(filepath.Join(dir, "nope.json")); err == nil ||
			!strings.Contains(err.Error(), "plaud-mcp-login") {
			t.Errorf("expected guidance to the login driver, got %v", err)
		}
	})
	t.Run("no access_token → error", func(t *testing.T) {
		p := write("empty.json", `{"refresh_token":"r"}`)
		if _, err := NewDevClientFromFile(p); err == nil {
			t.Error("expected error when access_token is absent")
		}
	})
}

func TestDevClient_ListAndDetail(t *testing.T) {
	var gotAuth string
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/open/third-party/files/") && len(r.URL.Path) > len("/open/third-party/files/"):
			id := strings.TrimPrefix(r.URL.Path, "/open/third-party/files/")
			fmt.Fprintf(w, `{"id":%q,"name":"rec","presigned_url":"https://b.s3-accelerate.amazonaws.com/x.mp3","source_list":[{"text":"seg one"},{"text":"seg two"}],"note_list":[{"content":"a note"}]}`, id)
		case r.URL.Path == "/open/third-party/files/":
			// page 1 → 100 items (full page → paginate), page 2 → 3 items (last page)
			if r.URL.Query().Get("page") == "1" {
				pages++
				items := make([]string, 100)
				for i := range items {
					items[i] = fmt.Sprintf(`{"id":"id%03d","name":"r%d","duration":1000}`, i, i)
				}
				fmt.Fprintf(w, `{"type":"list","data":[%s]}`, strings.Join(items, ","))
			} else {
				pages++
				fmt.Fprint(w, `{"type":"list","data":[{"id":"idX1"},{"id":"idX2"},{"id":"idX3"}]}`)
			}
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	c := &DevClient{token: "tok123", base: srv.URL, httpClient: srv.Client()}

	recs, err := c.ListRecordings()
	if err != nil {
		t.Fatalf("ListRecordings: %v", err)
	}
	if len(recs) != 103 {
		t.Errorf("paginated list = %d recordings, want 103", len(recs))
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization = %q, want 'Bearer tok123'", gotAuth)
	}

	d, err := c.GetDetail("711f200de464b5fcaea3bc0a375ec16f")
	if err != nil {
		t.Fatalf("GetDetail: %v", err)
	}
	if d.PresignedURL == "" {
		t.Error("expected a presigned_url")
	}
	if got := d.TranscriptText(); got != "seg one\nseg two" {
		t.Errorf("transcript = %q", got)
	}
	if got := d.NotesText(); got != "a note" {
		t.Errorf("notes = %q", got)
	}
}

func TestDevClient_DownloadAudio_HostGuard(t *testing.T) {
	c := &DevClient{token: "t", base: devAPIBase, httpClient: &http.Client{}}
	const guard = "allowed https S3 host"
	// Non-S3 host and an http downgrade must both be refused BEFORE any request.
	for _, bad := range []string{
		"https://evil.example/x.mp3",
		"http://b.s3-accelerate.amazonaws.com/x.mp3", // http → rejected (https required)
	} {
		_, err := c.DownloadAudio(bad)
		if err == nil || !strings.Contains(err.Error(), guard) {
			t.Errorf("DownloadAudio(%q) err = %v, want the S3-host guard to reject it", bad, err)
		}
	}
}
