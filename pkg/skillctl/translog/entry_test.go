package translog

import (
	"errors"
	"strings"
	"testing"
)

func goodEntry() LogEntry {
	return LogEntry{
		Type:      EventAttest,
		Digest:    "sha256:" + strings.Repeat("ab", 32),
		Timestamp: "2026-06-24T12:00:00Z",
		Subject:   "skill:my-skill",
	}
}

func TestLogEntry_CanonicalDeterministic(t *testing.T) {
	e := goodEntry()
	a, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("Canonical must be deterministic")
	}
	// Format check: exactly 5 LF-terminated lines, leading tag.
	want := "logentry-v1\nattest\nsha256:" + strings.Repeat("ab", 32) + "\n2026-06-24T12:00:00Z\nskill:my-skill\n"
	if string(a) != want {
		t.Fatalf("canonical bytes:\n got %q\nwant %q", string(a), want)
	}
}

func TestLogEntry_AllTypesValid(t *testing.T) {
	for _, ty := range []EventType{EventAdmit, EventAttest, EventRevoke, EventAgentIDIssue, EventAgentIDRevoke} {
		e := goodEntry()
		e.Type = ty
		if _, err := e.LeafHash(); err != nil {
			t.Fatalf("type %q should produce a leaf hash: %v", ty, err)
		}
	}
}

func TestLogEntry_RejectsBadFields(t *testing.T) {
	cases := []struct {
		name string
		mut  func(LogEntry) LogEntry
	}{
		{"unknown type", func(e LogEntry) LogEntry { e.Type = "frobnicate"; return e }},
		{"empty digest", func(e LogEntry) LogEntry { e.Digest = ""; return e }},
		{"uppercase digest", func(e LogEntry) LogEntry { e.Digest = "sha256:" + strings.Repeat("AB", 32); return e }},
		{"no prefix digest", func(e LogEntry) LogEntry { e.Digest = strings.Repeat("ab", 32); return e }},
		{"bad timestamp", func(e LogEntry) LogEntry { e.Timestamp = "yesterday"; return e }},
		{"subject newline", func(e LogEntry) LogEntry { e.Subject = "a\nb"; return e }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.mut(goodEntry()).Canonical(); !errors.Is(err, ErrEntryInvalid) {
				t.Fatalf("%s: want ErrEntryInvalid, got %v", c.name, err)
			}
		})
	}
}

// TestLogEntry_DistinctSubjectsDistinctLeaves: two events identical except
// for subject must hash to different leaves (no collision).
func TestLogEntry_DistinctSubjectsDistinctLeaves(t *testing.T) {
	a := goodEntry()
	b := goodEntry()
	b.Subject = "skill:other-skill"
	ha, _ := a.LeafHash()
	hb, _ := b.LeafHash()
	if ha == hb {
		t.Fatal("entries with different subjects must hash to different leaves")
	}
}

// TestLogEntry_NotConfusableWithRawLeaf: the "logentry-v1" tag plus the
// 0x00 leaf prefix means a crafted raw byte string can't trivially match a
// log entry's leaf hash.
func TestLogEntry_TaggedEncoding(t *testing.T) {
	e := goodEntry()
	canon, _ := e.Canonical()
	if !strings.HasPrefix(string(canon), "logentry-v1\n") {
		t.Fatal("canonical encoding must carry the logentry-v1 domain tag")
	}
}
