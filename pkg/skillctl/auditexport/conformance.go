// conformance.go: the Messvorrichtung of SPEC-0455 (unit T-00).
//
// ONE suite, every backend (REQ-4.2): a Backend implementation passes
// RunConformance or it does not ship. The suite tests the CONTRACT, never
// an implementation: it sees a backend only through the Backend interface
// plus the Harness observation hooks a test provides.
//
// Hermetics (REQ-6.2): the suite unsets the ambient ER1/M3C environment
// before every property, so an ambient registry or endpoint can never mask
// a violation (the H-F1 lesson). Stub backends live in the test files, not
// in this package's API.
//
// Calibration (claims rule 4, "a search proves nothing until it found a
// planted hit"): every property function below is exported to the package
// tests, and conformance_test.go runs each one against a planted violator
// that MUST fail. The mutation table lives beside those tests.
package auditexport

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
)

// Harness adapts one backend implementation to the suite.
type Harness struct {
	// New builds a fresh backend over a fresh, empty sink.
	New func(t *testing.T) Backend

	// Delivered inspects the sink and returns the payload per event id
	// as the sink holds it. Test-only observability; deliberately NOT
	// part of the Backend contract.
	Delivered func(t *testing.T) map[string][]byte

	// Tamper, when non-nil, makes the sink answer subsequent deliveries
	// with acknowledgements that must fail the backend's verification
	// (the tamper property, REQ-4.3). Nil skips the property (a backend
	// without verifiable acks has nothing to tamper with).
	Tamper func(t *testing.T)

	// FailEvent, when non-nil, makes the sink fail exactly this event id
	// on subsequent deliveries (the partial-failure property). Nil skips
	// the property.
	FailEvent func(t *testing.T, eventID string)
}

// RunConformance runs every applicable property against the harness.
func RunConformance(t *testing.T, h Harness) {
	t.Helper()
	if h.New == nil || h.Delivered == nil {
		t.Fatal("auditexport conformance: Harness.New and Harness.Delivered are required")
	}
	t.Run("ResultCoherent", func(t *testing.T) {
		unsetAmbientEnv(t)
		if err := CheckResultCoherent(t, h); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("AckHonesty", func(t *testing.T) {
		unsetAmbientEnv(t)
		if err := CheckAckHonesty(t, h); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("PayloadVerbatim", func(t *testing.T) {
		unsetAmbientEnv(t)
		if err := CheckPayloadVerbatim(t, h); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("RedeliveryIsNoOp", func(t *testing.T) {
		unsetAmbientEnv(t)
		if err := CheckRedeliveryIsNoOp(t, h); err != nil {
			t.Fatal(err)
		}
	})
	if h.Tamper != nil {
		t.Run("TamperedAckNeverSyncs", func(t *testing.T) {
			unsetAmbientEnv(t)
			if err := CheckTamperedAckNeverSyncs(t, h); err != nil {
				t.Fatal(err)
			}
		})
	}
	if h.FailEvent != nil {
		t.Run("PartialFailureIsPerEvent", func(t *testing.T) {
			unsetAmbientEnv(t)
			if err := CheckPartialFailureIsPerEvent(t, h); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// ambientEnv names the variables that could smuggle a real endpoint or
// credential into a suite run. Kept in one place so the hermetics claim
// has one carrier.
var ambientEnv = []string{
	"ER1_API_URL", "ER1_API_KEY", "ER1_DEVICE_TOKEN", "ER1_CONTEXT_ID",
	"M3C_INGEST_ENDPOINT",
}

// unsetAmbientEnv removes the ambient ER1/M3C environment for the duration
// of one test (restored by t.Setenv semantics on cleanup).
func unsetAmbientEnv(t *testing.T) {
	t.Helper()
	for _, k := range ambientEnv {
		if v, ok := os.LookupEnv(k); ok {
			// t.Setenv registers the restore; the explicit Unsetenv
			// leaves the variable ABSENT (not empty) during the test.
			t.Setenv(k, v)
			if err := os.Unsetenv(k); err != nil {
				t.Fatalf("unset %s: %v", k, err)
			}
		}
	}
}

func batchOf(ids ...string) []Record {
	b := make([]Record, 0, len(ids))
	for _, id := range ids {
		b = append(b, Record{EventID: id, Payload: []byte("payload-of-" + id)})
	}
	return b
}

// CheckResultCoherent: an event id appears in at most one Result field,
// and every reported id was part of the batch.
func CheckResultCoherent(t *testing.T, h Harness) error {
	b := h.New(t)
	batch := batchOf("ev-1", "ev-2", "ev-3")
	res, err := b.Deliver(context.Background(), batch)
	if err != nil {
		return fmt.Errorf("Deliver failed on a healthy sink: %w", err)
	}
	in := map[string]bool{}
	for _, r := range batch {
		in[r.EventID] = true
	}
	seen := map[string]string{}
	note := func(id, field string) error {
		if !in[id] {
			return fmt.Errorf("result names %q in %s, which was not in the batch", id, field)
		}
		if prev, dup := seen[id]; dup {
			return fmt.Errorf("event %q appears in both %s and %s", id, prev, field)
		}
		seen[id] = field
		return nil
	}
	for _, id := range res.Synced {
		if err := note(id, "Synced"); err != nil {
			return err
		}
	}
	for _, id := range res.Forwarded {
		if err := note(id, "Forwarded"); err != nil {
			return err
		}
	}
	for id := range res.Deferred {
		if err := note(id, "Deferred"); err != nil {
			return err
		}
	}
	return nil
}

// CheckAckHonesty: a backend declaring AckReceived can never report
// Synced (REQ-4.3, decision D6). The suite enforces the declaration, the
// drain enforces the second lock.
func CheckAckHonesty(t *testing.T, h Harness) error {
	b := h.New(t)
	res, err := b.Deliver(context.Background(), batchOf("ev-honesty"))
	if err != nil {
		return fmt.Errorf("Deliver failed on a healthy sink: %w", err)
	}
	if b.AckClass() == AckReceived && len(res.Synced) > 0 {
		return fmt.Errorf("backend declares AckReceived but reported %d event(s) as Synced", len(res.Synced))
	}
	if b.AckClass() == AckDurable && len(res.Synced) == 0 && len(res.Deferred) == 0 {
		return fmt.Errorf("durable backend on a healthy sink reported neither Synced nor Deferred")
	}
	return nil
}

// CheckPayloadVerbatim: the sink holds exactly the bytes the drain handed
// over (REQ-4.5: redaction ran before the seam, a backend never mutates).
func CheckPayloadVerbatim(t *testing.T, h Harness) error {
	b := h.New(t)
	batch := batchOf("ev-verbatim")
	if _, err := b.Deliver(context.Background(), batch); err != nil {
		return fmt.Errorf("Deliver failed on a healthy sink: %w", err)
	}
	got := h.Delivered(t)
	want := batch[0].Payload
	if !bytes.Equal(got["ev-verbatim"], want) {
		return fmt.Errorf("sink holds %q for ev-verbatim, want %q", got["ev-verbatim"], want)
	}
	return nil
}

// CheckRedeliveryIsNoOp: delivering the same event id twice leaves the
// sink with exactly one, unchanged copy, and the second delivery is
// acknowledged rather than deferred (REQ-4.6: replay is a safe no-op, so
// an interrupted drain can always retry).
func CheckRedeliveryIsNoOp(t *testing.T, h Harness) error {
	b := h.New(t)
	batch := batchOf("ev-replay")
	if _, err := b.Deliver(context.Background(), batch); err != nil {
		return fmt.Errorf("first Deliver failed: %w", err)
	}
	before := h.Delivered(t)["ev-replay"]
	res, err := b.Deliver(context.Background(), batch)
	if err != nil {
		return fmt.Errorf("redelivery failed: %w", err)
	}
	if _, deferred := res.Deferred["ev-replay"]; deferred {
		return fmt.Errorf("redelivery of ev-replay was deferred; replay must be an acknowledged no-op")
	}
	after := h.Delivered(t)
	if len(after) != 1 || !bytes.Equal(after["ev-replay"], before) {
		return fmt.Errorf("redelivery changed the sink: %d entries after replay", len(after))
	}
	return nil
}

// CheckTamperedAckNeverSyncs: with the sink answering acknowledgements
// that fail verification, nothing may be reported Synced; the events land
// in Deferred for retry (the double lock's backend half).
func CheckTamperedAckNeverSyncs(t *testing.T, h Harness) error {
	b := h.New(t)
	h.Tamper(t)
	res, err := b.Deliver(context.Background(), batchOf("ev-tamper"))
	if err != nil {
		// A batch-level error is acceptable fail-closed behavior;
		// Synced must still be empty.
		if len(res.Synced) > 0 {
			return fmt.Errorf("tampered ack: Deliver errored but still reported Synced")
		}
		return nil
	}
	if len(res.Synced) > 0 {
		return fmt.Errorf("tampered ack was reported as Synced; verification is not happening")
	}
	if _, ok := res.Deferred["ev-tamper"]; !ok && len(res.Forwarded) == 0 {
		return fmt.Errorf("tampered ack vanished: neither Deferred nor Forwarded")
	}
	return nil
}

// CheckPartialFailureIsPerEvent: one failing event defers that event, not
// the batch (REQ from the drain semantics: per-event outcomes, no
// all-or-nothing).
func CheckPartialFailureIsPerEvent(t *testing.T, h Harness) error {
	b := h.New(t)
	h.FailEvent(t, "ev-bad")
	res, err := b.Deliver(context.Background(), batchOf("ev-good", "ev-bad"))
	if err != nil {
		return fmt.Errorf("batch-level error for a single failing event: %w", err)
	}
	if _, ok := res.Deferred["ev-bad"]; !ok {
		return fmt.Errorf("failing event ev-bad is not in Deferred")
	}
	okSomewhere := false
	for _, id := range res.Synced {
		if id == "ev-good" {
			okSomewhere = true
		}
	}
	for _, id := range res.Forwarded {
		if id == "ev-good" {
			okSomewhere = true
		}
	}
	if !okSomewhere {
		return fmt.Errorf("healthy event ev-good did not get through beside a failing one")
	}
	return nil
}
