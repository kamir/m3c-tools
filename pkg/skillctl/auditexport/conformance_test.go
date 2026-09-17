// conformance_test.go: reference stubs + the calibration runs.
//
// The stubs model the two backend families: durableStub verifies a
// (simulated) acknowledgement before reporting Synced, the way the er1
// adapter verifies ed25519 durable-seq acks (T-01); receivedOnlyStub
// models an accepted-but-unproven transport (the future git backend).
//
// CALIBRATION TABLE (claims rule 4: a check proves nothing until it has
// failed a planted violation). Each property is run once against a stub
// built to violate exactly it:
//
//	property                  planted violator      violation
//	ResultCoherent            incoherentStub        same id in Synced and Forwarded
//	AckHonesty                lyingReceivedStub     AckReceived, reports Synced
//	PayloadVerbatim           mutatingStub          appends a byte to the payload
//	RedeliveryIsNoOp          duplicatingStub       replay grows the sink
//	TamperedAckNeverSyncs     trustingStub          skips ack verification
//	PartialFailureIsPerEvent  allOrNothingStub      one bad event fails the batch
package auditexport

import (
	"context"
	"errors"
	"os"
	"testing"
)

// memSink is the in-memory stand-in for a remote sink. tampered simulates
// a sink whose acknowledgements no longer verify; failID fails one event.
type memSink struct {
	store    map[string][]byte
	tampered bool
	failID   string
}

func newMemSink() *memSink { return &memSink{store: map[string][]byte{}} }

func (s *memSink) copyStore() map[string][]byte {
	out := make(map[string][]byte, len(s.store))
	for k, v := range s.store {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// put stores an event, deduplicating by event id (the sink-side half of
// REQ-4.6). Returns false when the ack for this write does not verify.
func (s *memSink) put(id string, payload []byte) (ackVerified bool) {
	if _, exists := s.store[id]; !exists {
		s.store[id] = append([]byte(nil), payload...)
	}
	return !s.tampered
}

// durableStub reports Synced only for verified acks; everything else is
// deferred for retry.
type durableStub struct{ sink *memSink }

func (b *durableStub) AckClass() AckClass { return AckDurable }

func (b *durableStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{Deferred: map[string]error{}}
	for _, r := range batch {
		if b.sink.failID == r.EventID {
			res.Deferred[r.EventID] = errors.New("sink failed this event")
			continue
		}
		if b.sink.put(r.EventID, r.Payload) {
			res.Synced = append(res.Synced, r.EventID)
		} else {
			res.Deferred[r.EventID] = errors.New("durable ack did not verify")
		}
	}
	return res, nil
}

// receivedOnlyStub accepts and stores, but can prove nothing durable.
type receivedOnlyStub struct{ sink *memSink }

func (b *receivedOnlyStub) AckClass() AckClass { return AckReceived }

func (b *receivedOnlyStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{Deferred: map[string]error{}}
	for _, r := range batch {
		if b.sink.failID == r.EventID {
			res.Deferred[r.EventID] = errors.New("sink failed this event")
			continue
		}
		b.sink.put(r.EventID, r.Payload)
		res.Forwarded = append(res.Forwarded, r.EventID)
	}
	return res, nil
}

func durableHarness() Harness {
	var s *memSink
	return Harness{
		New:       func(t *testing.T) Backend { s = newMemSink(); return &durableStub{sink: s} },
		Delivered: func(t *testing.T) map[string][]byte { return s.copyStore() },
		Tamper:    func(t *testing.T) { s.tampered = true },
		FailEvent: func(t *testing.T, id string) { s.failID = id },
	}
}

func receivedHarness() Harness {
	var s *memSink
	return Harness{
		New:       func(t *testing.T) Backend { s = newMemSink(); return &receivedOnlyStub{sink: s} },
		Delivered: func(t *testing.T) map[string][]byte { return s.copyStore() },
		FailEvent: func(t *testing.T, id string) { s.failID = id },
	}
}

func TestConformance_DurableStub(t *testing.T) {
	RunConformance(t, durableHarness())
}

func TestConformance_ReceivedOnlyStub(t *testing.T) {
	RunConformance(t, receivedHarness())
}

func TestHermetics_AmbientEnvAbsentDuringSuite(t *testing.T) {
	t.Setenv("ER1_API_URL", "https://ambient.example")
	t.Setenv("M3C_INGEST_ENDPOINT", "https://ambient.example/ingest")
	t.Run("inner", func(t *testing.T) {
		unsetAmbientEnv(t)
		for _, k := range []string{"ER1_API_URL", "M3C_INGEST_ENDPOINT"} {
			if _, ok := os.LookupEnv(k); ok {
				t.Fatalf("%s is still set inside the suite; hermetics broken", k)
			}
		}
	})
	if v := os.Getenv("ER1_API_URL"); v != "https://ambient.example" {
		t.Fatalf("ambient env not restored after the suite: %q", v)
	}
}

// ---- planted violators (calibration) ----

type incoherentStub struct{ sink *memSink }

func (b *incoherentStub) AckClass() AckClass { return AckDurable }
func (b *incoherentStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{}
	for _, r := range batch {
		b.sink.put(r.EventID, r.Payload)
		res.Synced = append(res.Synced, r.EventID)
		res.Forwarded = append(res.Forwarded, r.EventID) // violation
	}
	return res, nil
}

type lyingReceivedStub struct{ sink *memSink }

func (b *lyingReceivedStub) AckClass() AckClass { return AckReceived }
func (b *lyingReceivedStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{}
	for _, r := range batch {
		b.sink.put(r.EventID, r.Payload)
		res.Synced = append(res.Synced, r.EventID) // violation: received class
	}
	return res, nil
}

type mutatingStub struct{ sink *memSink }

func (b *mutatingStub) AckClass() AckClass { return AckDurable }
func (b *mutatingStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{}
	for _, r := range batch {
		b.sink.put(r.EventID, append(r.Payload, 'X')) // violation: mutation
		res.Synced = append(res.Synced, r.EventID)
	}
	return res, nil
}

type duplicatingStub struct{ sink *memSink }

func (b *duplicatingStub) AckClass() AckClass { return AckDurable }
func (b *duplicatingStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{}
	for _, r := range batch {
		if _, exists := b.sink.store[r.EventID]; exists {
			b.sink.store[r.EventID+"-dup"] = r.Payload // violation: replay grows the sink
		} else {
			b.sink.put(r.EventID, r.Payload)
		}
		res.Synced = append(res.Synced, r.EventID)
	}
	return res, nil
}

type trustingStub struct{ sink *memSink }

func (b *trustingStub) AckClass() AckClass { return AckDurable }
func (b *trustingStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	res := Result{}
	for _, r := range batch {
		b.sink.put(r.EventID, r.Payload) // ignores the verification result
		res.Synced = append(res.Synced, r.EventID)
	}
	return res, nil
}

type allOrNothingStub struct{ sink *memSink }

func (b *allOrNothingStub) AckClass() AckClass { return AckDurable }
func (b *allOrNothingStub) Deliver(_ context.Context, batch []Record) (Result, error) {
	for _, r := range batch {
		if b.sink.failID == r.EventID {
			return Result{}, errors.New("whole batch failed") // violation
		}
	}
	res := Result{}
	for _, r := range batch {
		b.sink.put(r.EventID, r.Payload)
		res.Synced = append(res.Synced, r.EventID)
	}
	return res, nil
}

func violatorHarness(build func(*memSink) Backend) Harness {
	var s *memSink
	return Harness{
		New:       func(t *testing.T) Backend { s = newMemSink(); return build(s) },
		Delivered: func(t *testing.T) map[string][]byte { return s.copyStore() },
		Tamper:    func(t *testing.T) { s.tampered = true },
		FailEvent: func(t *testing.T, id string) { s.failID = id },
	}
}

// TestCalibration_PlantedViolatorsFail proves each property catches the
// violation it was built for: the check must return a non-nil error.
func TestCalibration_PlantedViolatorsFail(t *testing.T) {
	cases := []struct {
		name  string
		check func(*testing.T, Harness) error
		h     Harness
	}{
		{"ResultCoherent/incoherentStub", CheckResultCoherent,
			violatorHarness(func(s *memSink) Backend { return &incoherentStub{sink: s} })},
		{"AckHonesty/lyingReceivedStub", CheckAckHonesty,
			violatorHarness(func(s *memSink) Backend { return &lyingReceivedStub{sink: s} })},
		{"PayloadVerbatim/mutatingStub", CheckPayloadVerbatim,
			violatorHarness(func(s *memSink) Backend { return &mutatingStub{sink: s} })},
		{"RedeliveryIsNoOp/duplicatingStub", CheckRedeliveryIsNoOp,
			violatorHarness(func(s *memSink) Backend { return &duplicatingStub{sink: s} })},
		{"TamperedAckNeverSyncs/trustingStub", CheckTamperedAckNeverSyncs,
			violatorHarness(func(s *memSink) Backend { return &trustingStub{sink: s} })},
		{"PartialFailureIsPerEvent/allOrNothingStub", CheckPartialFailureIsPerEvent,
			violatorHarness(func(s *memSink) Backend { return &allOrNothingStub{sink: s} })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(t, tc.h); err == nil {
				t.Fatalf("planted violation was NOT caught; the gauge is broken")
			}
		})
	}
}
