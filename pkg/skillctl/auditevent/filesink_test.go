package auditevent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestFileSinkWritesJSONL proves the default sink writes one well-formed JSON
// object per line (REQ-3.4) to a temp dir, with the parent directory created.
func TestFileSinkWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.jsonl") // parent must be created.
	fs, err := NewFileSink(path, 0)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })

	want := []EventType{EventSkillVerify, EventPolicyDeny, EventInvocationComplete}
	var ids []string
	for _, et := range want {
		e := New(et, OutcomeSuccess, SeverityInfo, "skillctl/x")
		ids = append(ids, e.EventID)
		if err := fs.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	f, err := os.Open(path) //nolint:gosec // test-controlled temp path.
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	var got []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line is not valid JSON: %v (%q)", err, sc.Text())
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("persisted line is not a valid event: %v", err)
		}
		got = append(got, e.EventID)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(ids) {
		t.Fatalf("line count: got %d want %d", len(got), len(ids))
	}
	for i := range ids {
		if got[i] != ids[i] {
			t.Fatalf("line %d id: got %q want %q (order/content mismatch)", i, got[i], ids[i])
		}
	}
}

// TestFileSinkRotates proves the file is rotated to "<path>.1" once it reaches
// maxBytes, bounding disk use.
func TestFileSinkRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fs, err := NewFileSink(path, 1) // 1 byte cap: rotate before the 2nd write.
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	e := New(EventSkillVerify, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := fs.Write(e); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := fs.Write(e); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated generation %q: %v", path+".1", err)
	}
}

// TestFileSinkPerms proves the file is created 0600 (REQ-5.3) on POSIX. Skipped
// on Windows where the numeric mode is not the relevant control (ACLs are).
func TestFileSinkPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits not meaningful on Windows (ACL discussion, REQ-5.3)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fs, err := NewFileSink(path, 0)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := fs.Write(New(EventConfigChange, OutcomeSuccess, SeverityInfo, "skillctl/x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("file perms: got %o want 0600", got)
	}
}

// TestFileSinkEmptyPath proves an empty path is refused.
func TestFileSinkEmptyPath(t *testing.T) {
	if _, err := NewFileSink("", 0); err == nil {
		t.Fatalf("empty path must be an error")
	}
}

// TestWriterSinkJSONL proves the stream sink emits one JSON line per event.
func TestWriterSinkJSONL(t *testing.T) {
	var buf bytes.Buffer
	s := NewWriterSink("stderr", &buf)
	if err := s.Write(New(EventSkillVerify, OutcomeSuccess, SeverityInfo, "skillctl/x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Write(New(EventPolicyDeny, OutcomeDeny, SeverityWarning, "skillctl/x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines := 0
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("not JSONL: %v", err)
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("want 2 JSONL lines, got %d", lines)
	}
}
