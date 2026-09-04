package auditevent

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestProducerString covers both branches of the producer-tag helper.
func TestProducerString(t *testing.T) {
	if got := ProducerString("0.4.0"); got != "skillctl/0.4.0" {
		t.Errorf("ProducerString: got %q", got)
	}
	if got := ProducerString(""); got != "skillctl" {
		t.Errorf("ProducerString empty: got %q", got)
	}
}

// TestNewStampsEnvelope proves the constructor fills the mandatory envelope so a
// New-built event validates without further setup.
func TestNewStampsEnvelope(t *testing.T) {
	e := New(EventSkillExecute, OutcomeSuccess, SeverityInfo, ProducerString("1.0"))
	if e.Schema != SchemaV1 || e.Timestamp == "" || e.EventID == "" {
		t.Fatalf("New did not stamp the envelope: %+v", e)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("New event must validate: %v", err)
	}
}

// TestSinkNamesAndClose covers the Name/Close surface used for observability.
func TestSinkNamesAndClose(t *testing.T) {
	fs, err := NewFileSink(filepath.Join(t.TempDir(), "a.jsonl"), 0)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if fs.Name() == "" || fs.Name()[:5] != "file:" {
		t.Errorf("FileSink.Name: %q", fs.Name())
	}
	if err := fs.Close(); err != nil {
		t.Errorf("FileSink.Close: %v", err)
	}
	ws := NewWriterSink("stderr", &bytes.Buffer{})
	if ws.Name() != "stderr" {
		t.Errorf("WriterSink.Name: %q", ws.Name())
	}
	if err := ws.Close(); err != nil {
		t.Errorf("WriterSink.Close: %v", err)
	}
}

// TestSinkNilEventGuards covers the nil-event guard on both concrete sinks.
func TestSinkNilEventGuards(t *testing.T) {
	fs, err := NewFileSink(filepath.Join(t.TempDir(), "a.jsonl"), 0)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := fs.Write(nil); err == nil {
		t.Errorf("FileSink.Write(nil) must error")
	}
	ws := NewWriterSink("w", &bytes.Buffer{})
	if err := ws.Write(nil); err == nil {
		t.Errorf("WriterSink.Write(nil) must error")
	}
}

// TestRedactNilEvent proves Redact tolerates a nil event.
func TestRedactNilEvent(t *testing.T) {
	DefaultRedactor().Redact(nil) // must not panic.
}

// TestIsRedactedValueEdges exercises the idempotency guard's boundaries: a
// non-string value, a real value that merely starts with the prefix but is the
// wrong length, and a non-hex tail are all treated as NOT already redacted.
func TestIsRedactedValueEdges(t *testing.T) {
	cases := map[string]bool{
		`123`:                    false, // not a string.
		`"sha256:abcdef012345"`:  true,  // 12 hex.
		`"sha256:abcdef01234"`:   false, // 11 chars, wrong length.
		`"sha256:zzzzzzzzzzzz"`:  false, // non-hex tail.
		`"[REDACTED]"`:           true,  // the drop marker.
		`"just a normal string"`: false,
	}
	for raw, want := range cases {
		if got := isRedactedValue([]byte(raw)); got != want {
			t.Errorf("isRedactedValue(%s): got %v want %v", raw, got, want)
		}
	}
}
