package auditevent

// localsink_test.go: the FR-0110b challenge-gate follow-up (2) test.
//
// REQ-6.10b requires a required-mode Dispatcher to be fulfilled at the LOCAL spool,
// never a broker ack, so a covered skill load path can never hang on a remote
// promise (the DoS the positive list bounds). NewDispatcherRequired now enforces
// this in CODE: it rejects any sink that is not a LocalSink. This test proves the
// rejection, and that the in-package local sinks are accepted.

import (
	"errors"
	"io"
	"testing"
)

// networkSink is a Sink that models a NETWORK-egress destination (a would-be Kafka
// sink, FR-0112). It deliberately does NOT implement the unexported localSink()
// marker, so it is not a LocalSink and must be rejected under required.
type networkSink struct{}

func (networkSink) Write(*Event) error { return nil }
func (networkSink) Name() string       { return "kafka://broker.example:9092" }
func (networkSink) Close() error       { return nil }

func TestNewDispatcherRequired_RejectsNonLocalSink(t *testing.T) {
	_, err := NewDispatcherRequired(policyAllowConfirmed(t), Redactor{}, networkSink{})
	if !errors.Is(err, ErrNonLocalSink) {
		t.Fatalf("a required-mode dispatcher must reject a non-local (network) sink with ErrNonLocalSink; got %v", err)
	}
}

func TestNewDispatcherRequired_RejectsMixedLocalAndNonLocal(t *testing.T) {
	// One good local sink and one network sink: the presence of ANY non-local sink
	// must fail construction (fail SAFE, closed), never silently drop the bad one.
	local := NewOutboxSinkWithStore(nil, t.TempDir())
	_, err := NewDispatcherRequired(policyAllowConfirmed(t), Redactor{}, local, networkSink{})
	if !errors.Is(err, ErrNonLocalSink) {
		t.Fatalf("a required-mode dispatcher must reject a batch containing any non-local sink; got %v", err)
	}
}

func TestNewDispatcherRequired_RejectsNoSink(t *testing.T) {
	_, err := NewDispatcherRequired(policyAllowConfirmed(t), Redactor{})
	if !errors.Is(err, ErrNonLocalSink) {
		t.Fatalf("a required-mode dispatcher with no sink can never be durably accepted; must be rejected; got %v", err)
	}
}

func TestNewDispatcherRequired_AcceptsLocalSinks(t *testing.T) {
	fs, err := NewFileSink(t.TempDir()+"/audit.jsonl", 0)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	local := []Sink{
		fs,
		NewWriterSink("stderr", io.Discard),
		NewOutboxSinkWithStore(nil, t.TempDir()),
		&failingSink{}, // a LOCAL sink that fails writes is still local (no network).
	}
	for _, s := range local {
		d, err := NewDispatcherRequired(policyAllowConfirmed(t), Redactor{}, s)
		if err != nil {
			t.Fatalf("local sink %q must be accepted under required; got %v", s.Name(), err)
		}
		if d == nil || d.Mode() != ModeRequired {
			t.Fatalf("expected a required-mode dispatcher for local sink %q", s.Name())
		}
	}
}

// isLocalSink correctly classifies the in-package sinks and rejects a foreign one.
func TestIsLocalSink_Classification(t *testing.T) {
	fs, _ := NewFileSink(t.TempDir()+"/a.jsonl", 0)
	locals := []Sink{fs, NewWriterSink("x", io.Discard), NewOutboxSinkWithStore(nil, t.TempDir())}
	for _, s := range locals {
		if !isLocalSink(s) {
			t.Fatalf("%q must classify as a LocalSink", s.Name())
		}
	}
	if isLocalSink(networkSink{}) {
		t.Fatal("a network sink must NOT classify as a LocalSink")
	}
}
