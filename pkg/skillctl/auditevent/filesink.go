package auditevent

// filesink.go: the default, infrastructure-free sinks (SPEC-0403 §5). Audit
// logging is on by default and works with no external infrastructure (REQ-5.1);
// the standard targets are file, stderr and stdout (REQ-5.2). JSON Lines is the
// canonical form; one event object per line (REQ-3.4). Files are created with
// restrictive, platform-appropriate permissions; the landed 0o600 append path
// is the reference (REQ-5.3), matching cmd/skillctl/gate_audit.go and
// pkg/skillctl/outbox/spool.go.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// DefaultFileSinkMaxBytes bounds a FileSink's live file; beyond it the file is
// rotated to "<path>.1" (single generation) so disk use stays bounded, mirroring
// the SPEC-0255 gate-audit rotation.
const DefaultFileSinkMaxBytes int64 = 5 << 20 // 5 MiB.

// FileSink appends redacted audit events as JSON Lines to a single file. It is
// the §5 default local sink. Safe for concurrent Write via an internal mutex.
type FileSink struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

// NewFileSink returns a FileSink writing JSONL to path. The parent directory is
// created 0o700 on first Write. maxBytes ≤ 0 selects DefaultFileSinkMaxBytes.
// An empty path is an error (there is nowhere to write).
func NewFileSink(path string, maxBytes int64) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("auditevent: file sink needs a path")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultFileSinkMaxBytes
	}
	return &FileSink{path: path, maxBytes: maxBytes}, nil
}

// Name identifies the sink as "file:<path>" for observability (FR-0111).
func (f *FileSink) Name() string { return "file:" + f.path }

// Write appends one event as a single JSON line. It creates the parent directory
// (0o700) and the file (0o600) as needed, rotating first if the file has reached
// maxBytes. A best-effort rotation race only costs one extra line in the old
// generation; the record is advisory, never load-bearing.
func (f *FileSink) Write(e *Event) error {
	if e == nil {
		return fmt.Errorf("auditevent: file sink: nil event")
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("auditevent: file sink: marshal: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("auditevent: file sink: mkdir: %w", err)
	}
	if fi, err := os.Stat(f.path); err == nil && fi.Size() >= f.maxBytes {
		_ = os.Rename(f.path, f.path+".1") // best-effort rotation; a lost race is harmless.
	}
	// #nosec G304 -- the audit sink path is operator-configured (SPEC-0403 §5,
	// REQ-5.3), not attacker-influenced; opened append-only 0o600, same pattern
	// as the landed gate_audit.go / outbox spool sinks.
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("auditevent: file sink: open: %w", err)
	}
	if _, err := fh.Write(append(line, '\n')); err != nil {
		_ = fh.Close() // returning the write error; close is best-effort on the failure path.
		return fmt.Errorf("auditevent: file sink: write: %w", err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("auditevent: file sink: close: %w", err)
	}
	return nil
}

// Close is a no-op: FileSink holds no long-lived handle (it opens and closes per
// Write so a rotation or external truncation is always observed).
func (f *FileSink) Close() error { return nil }

// WriterSink emits redacted audit events as JSON Lines to any io.Writer; the
// stderr / stdout targets of REQ-5.2. It never closes the underlying writer
// (stderr/stdout are process-owned). Safe for concurrent Write via a mutex.
type WriterSink struct {
	name string
	w    io.Writer
	mu   sync.Mutex
}

// NewWriterSink returns a WriterSink writing JSONL to w. name labels it for
// observability, e.g. "stderr".
func NewWriterSink(name string, w io.Writer) *WriterSink {
	return &WriterSink{name: name, w: w}
}

// Name identifies the sink for observability (FR-0111).
func (s *WriterSink) Name() string { return s.name }

// Write emits one event as a single JSON line to the underlying writer.
func (s *WriterSink) Write(e *Event) error {
	if e == nil {
		return fmt.Errorf("auditevent: writer sink: nil event")
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("auditevent: writer sink: marshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("auditevent: writer sink: write: %w", err)
	}
	return nil
}

// Close is a no-op: the underlying writer is process-owned and not closed here.
func (s *WriterSink) Close() error { return nil }
