package main

// sync_auditexport_conformance_test.go: SPEC-0455 T-01 (S7). The shared
// backend conformance suite (pkg/skillctl/auditexport) runs against the
// REAL er1 adapter, with the sink played by an httptest TLS double that
// speaks the ingest ACK contract (same family as contractDouble in
// sync_cmds_test.go, but with mutable hooks). Tamper = acks signed by the
// WRONG key, so VerifyAck must reject them; FailEvent = the double omits
// that event's ack, so exactly that event must be deferred.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditexport"
	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
)

// er1ConformanceSink is the mutable ingest double behind one harness run:
// dedups by event_id, signs durable acks, can be tampered or told to fail
// one event.
type er1ConformanceSink struct {
	mu       sync.Mutex
	store    map[string][]byte
	seq      int64
	tampered bool
	failID   string
}

func newER1ConformanceHarness(t *testing.T) auditexport.Harness {
	t.Helper()
	ingest := syncTestIngestKey(t)
	wrongKey := syncTestDeviceKey(t)
	pub, _ := ingest.Public().(ed25519.PublicKey)
	const logID = "conformance-log"

	var s *er1ConformanceSink
	newBackend := func(t *testing.T) auditexport.Backend {
		sink := &er1ConformanceSink{store: map[string][]byte{}}
		s = sink
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var batch outbox.IngestBatch
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &batch)
			sink.mu.Lock()
			defer sink.mu.Unlock()
			var acks []outbox.DurableAck
			for _, raw := range batch.Records {
				var rec struct {
					EventID string `json:"event_id"`
				}
				if err := json.Unmarshal(raw, &rec); err != nil || rec.EventID == "" {
					continue
				}
				if rec.EventID == sink.failID {
					continue // no ack: this event must end up deferred
				}
				if _, exists := sink.store[rec.EventID]; !exists {
					sink.store[rec.EventID] = append([]byte(nil), raw...)
				}
				sink.seq++
				key := ingest
				if sink.tampered {
					key = wrongKey // ack signature must NOT verify
				}
				sig := ed25519.Sign(key, outbox.CanonicalDurableSeq(logID, rec.EventID, sink.seq))
				acks = append(acks, outbox.DurableAck{
					EventID: rec.EventID, DurableSeq: sink.seq, SeqSigB64: base64.StdEncoding.EncodeToString(sig),
				})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(outbox.IngestResponse{Acks: acks})
		}))
		t.Cleanup(srv.Close)

		client := &outbox.IngestClient{
			Endpoint:    srv.URL,
			Token:       "conformance-token",
			LogID:       logID,
			PubKey:      pub,
			Client:      srv.Client(),
			ClientEpoch: time.Now().Unix(),
		}
		b, err := auditexport.New("er1", client)
		if err != nil {
			t.Fatalf("auditexport.New: %v", err)
		}
		return b
	}

	return auditexport.Harness{
		New: newBackend,
		Delivered: func(t *testing.T) map[string][]byte {
			s.mu.Lock()
			defer s.mu.Unlock()
			out := make(map[string][]byte, len(s.store))
			for k, v := range s.store {
				out[k] = append([]byte(nil), v...)
			}
			return out
		},
		Tamper:    func(t *testing.T) { s.mu.Lock(); s.tampered = true; s.mu.Unlock() },
		FailEvent: func(t *testing.T, id string) { s.mu.Lock(); s.failID = id; s.mu.Unlock() },
		// The er1 ingest contract derives the event id from the signed
		// envelope in the payload (REQ-4.4), so the suite's payloads must
		// carry it the same way.
		Encode: func(eventID string) []byte {
			b, _ := json.Marshal(map[string]string{"event_id": eventID, "suite": "auditexport-conformance"})
			return b
		},
	}
}

func TestConformance_ER1Backend(t *testing.T) {
	auditexport.RunConformance(t, newER1ConformanceHarness(t))
}

// TestRegister_UnknownBackendNamed pins the register's refusal wording:
// the known-name list is the population the message quotes (A4 groundwork).
func TestRegister_UnknownBackendNamed(t *testing.T) {
	_, err := auditexport.New("git", nil)
	if err == nil {
		t.Fatal("unknown backend name was accepted")
	}
	want := `unknown audit export backend "git" (known: er1)`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}
