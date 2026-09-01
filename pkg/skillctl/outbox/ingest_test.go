package outbox

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ingestKey is a fixed ingest signing key so durable-seq acks are deterministic.
var ingestKey = func() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	return ed25519.NewKeyFromSeed(seed)
}()

func signDurable(logID, eventID string, seq int64) string {
	sig := ed25519.Sign(ingestKey, CanonicalDurableSeq(logID, eventID, seq))
	return base64.StdEncoding.EncodeToString(sig)
}

func TestIngest_PostBatch_RejectsNonHTTPS(t *testing.T) {
	c := &IngestClient{Endpoint: "http://example.com", LogID: "L"}
	if _, _, err := c.PostBatch(context.Background(), [][]byte{[]byte(`{}`)}); err == nil {
		t.Fatal("expected https-only rejection, got nil error")
	}
}

func TestIngest_PostBatch_ParsesSignedAcks(t *testing.T) {
	var gotBody IngestBatch
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != IngestPath {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		resp := IngestResponse{Acks: []DurableAck{
			{EventID: "inv:1", DurableSeq: 7, SeqSigB64: signDurable("L", "inv:1", 7)},
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := &IngestClient{
		Endpoint: srv.URL, LogID: "L", PubKey: ingestKey.Public().(ed25519.PublicKey),
		Client: srv.Client(), ClientEpoch: 99,
	}
	resp, status, err := c.PostBatch(context.Background(), [][]byte{[]byte(`{"event_id":"inv:1"}`)})
	if err != nil {
		t.Fatalf("PostBatch: %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if gotBody.ClientEpoch != 99 || len(gotBody.Records) != 1 {
		t.Fatalf("body not forwarded verbatim: %+v", gotBody)
	}
	if len(resp.Acks) != 1 || !c.VerifyAck(resp.Acks[0]) {
		t.Fatalf("ack did not verify: %+v", resp.Acks)
	}
}

func TestIngest_VerifyAck(t *testing.T) {
	c := &IngestClient{LogID: "L", PubKey: ingestKey.Public().(ed25519.PublicKey)}

	// Valid.
	if !c.VerifyAck(DurableAck{EventID: "e1", DurableSeq: 3, SeqSigB64: signDurable("L", "e1", 3)}) {
		t.Fatal("valid ack should verify")
	}
	// Wrong seq (signature is over a different message).
	if c.VerifyAck(DurableAck{EventID: "e1", DurableSeq: 4, SeqSigB64: signDurable("L", "e1", 3)}) {
		t.Fatal("tampered seq must not verify")
	}
	// Wrong log id.
	if c.VerifyAck(DurableAck{EventID: "e1", DurableSeq: 3, SeqSigB64: signDurable("OTHER", "e1", 3)}) {
		t.Fatal("wrong log id must not verify")
	}
	// Empty signature (bare-2xx shape).
	if c.VerifyAck(DurableAck{EventID: "e1", DurableSeq: 3}) {
		t.Fatal("empty sig must not verify")
	}
	// No pubkey → fail-closed.
	noKey := &IngestClient{LogID: "L"}
	if noKey.VerifyAck(DurableAck{EventID: "e1", DurableSeq: 3, SeqSigB64: signDurable("L", "e1", 3)}) {
		t.Fatal("missing pubkey must fail closed")
	}
}
