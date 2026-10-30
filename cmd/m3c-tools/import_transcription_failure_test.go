//go:build !windows

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const failingWhisper = "#!/bin/sh\necho simulated crash >&2\nexit 1\n"

const workingWhisper = `#!/bin/sh
out=""; in=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output_dir) out="$2"; shift 2 ;;
    --*) shift 2 ;;
    *) in="$1"; shift ;;
  esac
done
base=$(basename "$in"); base="${base%.*}"
printf '{"text":"spoken words","segments":[],"language":"en"}' > "$out/$base.json"
`

func installFakeWhisper(t *testing.T, dir, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "whisper"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestImportFailedTranscriptionIsNotUploadedAndCanBeRetried(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	t.Setenv("M3C_TOKEN_STORE", "file")

	var uploads atomic.Int32
	var lastBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastBody.Store(string(body))
		uploads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"doc_id":"fake-1"}`))
	}))
	defer srv.Close()
	t.Setenv("ER1_API_URL", srv.URL+"/upload_2")
	t.Setenv("ER1_API_KEY", "test-key-not-a-credential")
	t.Setenv("ER1_CONTEXT_ID", "test___mft")

	bin := t.TempDir()
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	inbox := t.TempDir()
	if err := os.WriteFile(filepath.Join(inbox, "note.wav"), []byte("RIFF-not-really-audio"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IMPORT_AUDIO_DEST", filepath.Join(home, "ER1"))
	dbPath := filepath.Join(home, "files.db")

	installFakeWhisper(t, bin, failingWhisper)
	summary, err := runAudioImportPipeline(inbox, dbPath, "", nil, nil)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if summary.Failed != 1 || summary.Uploaded != 0 {
		t.Fatalf("failed transcription: summary = %+v, want Failed=1 Uploaded=0", summary)
	}
	if got := uploads.Load(); got != 0 {
		t.Fatalf("failed transcription reached the server %d time(s)", got)
	}

	installFakeWhisper(t, bin, workingWhisper)
	summary, err = runAudioImportPipeline(inbox, dbPath, "", nil, nil)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if summary.Uploaded != 1 || summary.Failed != 0 {
		t.Fatalf("after whisper works: summary = %+v, want Uploaded=1 Failed=0", summary)
	}
	body, _ := lastBody.Load().(string)
	if !strings.Contains(body, "spoken words") {
		t.Fatalf("upload does not carry the transcript: %.300s", body)
	}
}
