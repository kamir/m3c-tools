package translog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tmpLogPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "transparency-log.jsonl")
}

func mkEntry(ty EventType, n int) LogEntry {
	// Deterministic digest from n.
	d := "sha256:" + strings.Repeat("0", 63) + itoa(n%10)
	return LogEntry{
		Type:      ty,
		Digest:    d,
		Timestamp: "2026-06-24T12:00:0" + itoa(n%10) + "Z",
		Subject:   "subject-" + itoa(n),
	}
}

func TestLog_AppendAndProve(t *testing.T) {
	path := tmpLogPath(t)
	l, err := OpenLog(path, "skillctl-log-test")
	if err != nil {
		t.Fatal(err)
	}
	var idxs []int
	for i := 0; i < 7; i++ {
		idx, err := l.Append(mkEntry(EventAttest, i))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		idxs = append(idxs, idx)
	}
	if l.Size() != 7 {
		t.Fatalf("size = %d, want 7", l.Size())
	}

	root, err := l.Root()
	if err != nil {
		t.Fatal(err)
	}
	// Every appended entry must have a verifiable inclusion proof against
	// the current root.
	for _, idx := range idxs {
		proof, size, leaf, err := l.ProveInclusion(idx)
		if err != nil {
			t.Fatalf("prove idx %d: %v", idx, err)
		}
		if err := VerifyInclusion(leaf, idx, size, proof, root); err != nil {
			t.Fatalf("verify inclusion idx %d: %v", idx, err)
		}
	}
}

func TestLog_PersistAndReload(t *testing.T) {
	path := tmpLogPath(t)
	l, err := OpenLog(path, "log-A")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append(mkEntry(EventAdmit, i)); err != nil {
			t.Fatal(err)
		}
	}
	rootBefore, _ := l.Root()

	// Reopen from disk: same entries, same root (append-only persistence).
	l2, err := OpenLog(path, "log-A")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if l2.Size() != 5 {
		t.Fatalf("reloaded size = %d, want 5", l2.Size())
	}
	rootAfter, _ := l2.Root()
	if rootBefore != rootAfter {
		t.Fatal("root changed across reload — persistence is not faithful")
	}
}

func TestLog_SignHeadAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, _ := OpenLog(tmpLogPath(t), "log-A")
	for i := 0; i < 4; i++ {
		if _, err := l.Append(mkEntry(EventRevoke, i)); err != nil {
			t.Fatal(err)
		}
	}
	sth, err := l.SignHead(priv, time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySTH(pub, sth); err != nil {
		t.Fatalf("STH should verify: %v", err)
	}
	if sth.TreeSize != 4 || sth.LogID != "log-A" {
		t.Fatalf("STH fields wrong: %+v", sth)
	}
	// The STH root must match the tree root, and an inclusion proof must
	// verify against it.
	root, _ := sth.RootBytes()
	proof, size, leaf, _ := l.ProveInclusion(2)
	if err := VerifyInclusion(leaf, 2, size, proof, root); err != nil {
		t.Fatalf("inclusion under STH root failed: %v", err)
	}
}

func TestLog_ConsistencyAcrossGrowth(t *testing.T) {
	l, _ := OpenLog(tmpLogPath(t), "log-A")
	for i := 0; i < 4; i++ {
		if _, err := l.Append(mkEntry(EventAttest, i)); err != nil {
			t.Fatal(err)
		}
	}
	rootAt4, _ := l.Root()

	for i := 4; i < 10; i++ {
		if _, err := l.Append(mkEntry(EventAttest, i)); err != nil {
			t.Fatal(err)
		}
	}
	rootAt10, _ := l.Root()

	proof, second, err := l.ProveConsistency(4)
	if err != nil {
		t.Fatal(err)
	}
	if second != 10 {
		t.Fatalf("second = %d, want 10", second)
	}
	if err := VerifyConsistency(4, 10, rootAt4, rootAt10, proof); err != nil {
		t.Fatalf("growth must be append-consistent: %v", err)
	}
}

func TestLog_RejectsCorruptLine(t *testing.T) {
	path := tmpLogPath(t)
	// Hand-write a file with a valid line then garbage.
	l, _ := OpenLog(path, "log-A")
	if _, err := l.Append(mkEntry(EventAdmit, 1)); err != nil {
		t.Fatal(err)
	}
	if err := appendRaw(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLog(path, "log-A"); err == nil {
		t.Fatal("expected reload to fail on corrupt line (silent skip would hide tampering)")
	}
}

func TestLog_FindByDigest(t *testing.T) {
	l, _ := OpenLog(tmpLogPath(t), "log-A")
	e := mkEntry(EventAttest, 3)
	if _, err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	hits := l.FindByDigest(e.Digest)
	if len(hits) != 1 || hits[0] != 0 {
		t.Fatalf("FindByDigest = %v, want [0]", hits)
	}
	if got := l.FindByDigest("sha256:" + strings.Repeat("f", 64)); len(got) != 0 {
		t.Fatalf("unknown digest should find nothing, got %v", got)
	}
}

func TestLog_BadLogID(t *testing.T) {
	if _, err := OpenLog(tmpLogPath(t), "bad id with spaces"); !errors.Is(err, ErrLogIDRequired) {
		t.Fatalf("want ErrLogIDRequired, got %v", err)
	}
}

func TestLog_WriteJSONLinesRoundTrips(t *testing.T) {
	l, _ := OpenLog(tmpLogPath(t), "log-A")
	for i := 0; i < 3; i++ {
		if _, err := l.Append(mkEntry(EventAttest, i)); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := l.writeJSONLines(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 JSONL lines, got %d", len(lines))
	}
}

// appendRaw appends a raw line to a file (test helper for corruption).
func appendRaw(path, line string) error {
	l := &Log{path: path}
	return l.appendLine([]byte(line))
}
