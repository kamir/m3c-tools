package main

// sync_cmds_test.go — SPEC-0317 AC-4 against a CONTRACT DOUBLE (httptest).
//
// No real Kafka, no real backend: the double is an httptest.NewTLSServer that
// mimics the ingest ACK contract. The four AC-4 assertions:
//   - valid signed durable-seq  → row marked synced.
//   - bare-2xx (no durable-seq)  → row NOT synced (+ a delivery_attempts row).
//   - replay of an acked event   → client no-op (drain set is empty; no re-post).
//   - 5xx transient              → row NOT synced (+ a delivery_attempts backoff row).
// Plus: 4xx → exit 29 (ingest_rejected); HTTPS-only; loopback-gated --insecure.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// --- fixtures -----------------------------------------------------------------

func syncTestDeviceKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func syncTestIngestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x80 + i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// writeIngestPubPEM writes an ed25519 pubkey as SPKI PEM (the form
// signing.LoadPublicKey accepts) and returns the path.
func writeIngestPubPEM(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	p := filepath.Join(dir, "ingest.pub.pem")
	blk := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(p, blk, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return p
}

// appendSignedRow builds, signs and appends one InvocationRecord to the store.
func appendSignedRow(t *testing.T, store *outbox.Store, priv ed25519.PrivateKey, keyID, eventID, occurred string) {
	t.Helper()
	rec := skillgate.InvocationRecord{
		Schema:      skillgate.InvocationSchema,
		EventID:     eventID,
		EventType:   "skill.invocation",
		SkillName:   "demo",
		SkillDigest: "sha256:cafe",
		Tool:        "Skill",
		OccurredAt:  occurred,
		DeviceKeyID: keyID,
	}
	if err := skillgate.SignInvocationRecord(&rec, func(m []byte) []byte { return ed25519.Sign(priv, m) }, base64.StdEncoding.EncodeToString); err != nil {
		t.Fatalf("sign: %v", err)
	}
	pj, ph, err := outbox.RecordPayload(rec)
	if err != nil {
		t.Fatalf("RecordPayload: %v", err)
	}
	if err := store.Append(rec, pj, ph); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

// ackMode selects the contract double's behaviour.
type ackMode int

const (
	ackDurable ackMode = iota // valid signed durable-seq for every record
	ackBare                   // 2xx, empty acks (no durable-seq)
	ack5xx                    // 500
	ack4xx                    // 401
)

// contractDouble is an httptest.NewTLSServer that mimics the ingest ACK
// contract. It counts posts and echoes signed durable-seqs in ackDurable mode.
func contractDouble(t *testing.T, ingest ed25519.PrivateKey, logID string, mode ackMode, posts *int32) *httptest.Server {
	t.Helper()
	var seq int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(posts, 1)
		var batch outbox.IngestBatch
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &batch)
		switch mode {
		case ack5xx:
			w.WriteHeader(http.StatusInternalServerError)
			return
		case ack4xx:
			w.WriteHeader(http.StatusUnauthorized)
			return
		case ackBare:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(outbox.IngestResponse{})
			return
		case ackDurable:
			var acks []outbox.DurableAck
			for _, raw := range batch.Records {
				var rec skillgate.InvocationRecord
				if err := json.Unmarshal(raw, &rec); err != nil {
					continue
				}
				seq++
				sig := ed25519.Sign(ingest, outbox.CanonicalDurableSeq(logID, rec.EventID, seq))
				acks = append(acks, outbox.DurableAck{
					EventID: rec.EventID, DurableSeq: seq, SeqSigB64: base64.StdEncoding.EncodeToString(sig),
				})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(outbox.IngestResponse{Acks: acks})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// syncHarness wires HOME + the device-pub seam and returns an opened store.
func syncHarness(t *testing.T, priv ed25519.PrivateKey, keyID string) (home string, store *outbox.Store) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ER1_DEVICE_TOKEN", "test-token")
	pub := priv.Public().(ed25519.PublicKey)
	orig := syncResolveDevicePub
	syncResolveDevicePub = func(h, id string) (ed25519.PublicKey, bool) {
		if id == keyID {
			return pub, true
		}
		return nil, false
	}
	t.Cleanup(func() { syncResolveDevicePub = orig })

	s, err := outbox.Open(home)
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return home, s
}

func reopenStore(t *testing.T, home string) *outbox.Store {
	t.Helper()
	s, err := outbox.Open(home)
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// --- AC-4 -----------------------------------------------------------------

func TestSync_AC4_DurableSeqMarksSynced(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "device:test", "skillctl-local"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:0000000000001:aa", "2026-07-08T10:00:00Z")
	appendSignedRow(t, store, dev, keyID, "inv:0000000000002:bb", "2026-07-08T10:00:01Z")
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ackDurable, &posts)

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, errb.String())
	}

	s := reopenStore(t, home)
	if n, _ := s.PendingCount(); n != 0 {
		t.Fatalf("pending after sync = %d, want 0", n)
	}
	for _, id := range []string{"inv:0000000000001:aa", "inv:0000000000002:bb"} {
		ev, ok, _ := s.Get(id)
		if !ok || ev.SyncStatus != 1 || ev.SyncedAt == "" {
			t.Fatalf("row %s not marked synced: %+v", id, ev)
		}
	}
}

func TestSync_AC4_BareTwoXXDoesNotMarkSynced(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "device:test", "skillctl-local"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:0000000000010:aa", "2026-07-08T10:00:00Z")
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ackBare, &posts)

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, errb.String())
	}

	s := reopenStore(t, home)
	ev, ok, _ := s.Get("inv:0000000000010:aa")
	if !ok || ev.SyncStatus != 0 {
		t.Fatalf("bare-2xx must NOT mark synced: %+v", ev)
	}
	att, _ := s.Attempts("inv:0000000000010:aa")
	if len(att) != 1 {
		t.Fatalf("want 1 delivery attempt after bare-2xx, got %d", len(att))
	}
	if atomic.LoadInt32(&posts) != 1 {
		t.Fatalf("want exactly 1 post, got %d", posts)
	}
}

func TestSync_AC4_ReplayIsNoOp(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "device:test", "skillctl-local"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:0000000000020:aa", "2026-07-08T10:00:00Z")
	// Replay: appending the SAME event_id again is an INSERT OR IGNORE no-op.
	appendSignedRow(t, store, dev, keyID, "inv:0000000000020:aa", "2026-07-08T10:00:00Z")
	if n, _ := store.PendingCount(); n != 1 {
		t.Fatalf("duplicate event_id must not create a 2nd row; pending=%d", n)
	}
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ackDurable, &posts)

	args := []string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}
	var out, errb bytes.Buffer
	if code := runSync(args, &out, &errb); code != syncExitOK {
		t.Fatalf("first sync exit=%d; stderr=%s", code, errb.String())
	}
	// Second run: the row is already synced, so the drain set is empty and no
	// new POST is made — a client-side no-op.
	out.Reset()
	errb.Reset()
	if code := runSync(args, &out, &errb); code != syncExitOK {
		t.Fatalf("replay sync exit=%d; stderr=%s", code, errb.String())
	}
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("replay must not re-post an acked event; posts=%d, want 1", got)
	}
}

func TestSync_AC4_FiveXXBacksOff(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "device:test", "skillctl-local"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:0000000000030:aa", "2026-07-08T10:00:00Z")
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ack5xx, &posts)

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit = %d, want 0 (transient is not fatal); stderr=%s", code, errb.String())
	}

	s := reopenStore(t, home)
	ev, ok, _ := s.Get("inv:0000000000030:aa")
	if !ok || ev.SyncStatus != 0 {
		t.Fatalf("5xx must NOT mark synced: %+v", ev)
	}
	att, _ := s.Attempts("inv:0000000000030:aa")
	if len(att) != 1 {
		t.Fatalf("want 1 backoff attempt after 5xx, got %d", len(att))
	}
	if att[0].NextRetryAt == "" || att[0].HTTPStatus != 500 {
		t.Fatalf("backoff row malformed: %+v", att[0])
	}
}

func TestSync_FourXXExitsIngestRejected(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "device:test", "skillctl-local"
	home, store := syncHarness(t, dev, keyID)
	appendSignedRow(t, store, dev, keyID, "inv:0000000000040:aa", "2026-07-08T10:00:00Z")
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ack4xx, &posts)

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitIngestRejected {
		t.Fatalf("exit = %d, want %d (ingest_rejected); stderr=%s", code, syncExitIngestRejected, errb.String())
	}
}

// --- egress posture + transport hardening ---------------------------------

func TestSync_EgressDefaultOff(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("M3C_INGEST_ENDPOINT", "")
	var out, errb bytes.Buffer
	code := runSync([]string{"--once"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !bytes.Contains(out.Bytes(), []byte("egress disabled")) {
		t.Fatalf("expected default-off notice, got %q", out.String())
	}
}

func TestSync_InsecureRejectedForNonLoopback(t *testing.T) {
	_, err := buildIngestClient("https://ingest.example.com", "", "L", true, io.Discard)
	if err == nil {
		t.Fatal("--insecure against a non-loopback endpoint must be rejected")
	}
}

func TestSync_RejectsNonHTTPSEndpoint(t *testing.T) {
	_, err := buildIngestClient("http://ingest.example.com", "", "L", false, io.Discard)
	if err == nil {
		t.Fatal("non-https endpoint must be rejected (HTTPS-only)")
	}
}

func TestSync_TamperedRowNotShipped(t *testing.T) {
	dev := syncTestDeviceKey(t)
	ingest := syncTestIngestKey(t)
	const keyID, logID = "device:test", "skillctl-local"
	home, store := syncHarness(t, dev, keyID)

	// Build a valid record, then corrupt the payload_hash column so it diverges
	// from the payload_json bytes (a tamper signal). Such a row must not ship.
	rec := skillgate.InvocationRecord{
		Schema: skillgate.InvocationSchema, EventID: "inv:0000000000050:aa", EventType: "skill.invocation",
		SkillName: "demo", Tool: "Skill", OccurredAt: "2026-07-08T10:00:00Z", DeviceKeyID: keyID,
	}
	if err := skillgate.SignInvocationRecord(&rec, func(m []byte) []byte { return ed25519.Sign(dev, m) }, base64.StdEncoding.EncodeToString); err != nil {
		t.Fatalf("sign: %v", err)
	}
	pj, _, _ := outbox.RecordPayload(rec)
	if err := store.Append(rec, pj, "deadbeefdivergenthash"); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = store.Close()

	pemPath := writeIngestPubPEM(t, home, ingest.Public().(ed25519.PublicKey))
	var posts int32
	srv := contractDouble(t, ingest, logID, ackDurable, &posts)

	var out, errb bytes.Buffer
	code := runSync([]string{"--once", "--endpoint", srv.URL, "--ingest-pubkey", pemPath, "--log-id", logID, "--insecure"}, &out, &errb)
	if code != syncExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if atomic.LoadInt32(&posts) != 0 {
		t.Fatalf("a divergent row must not be posted; posts=%d", posts)
	}
	s := reopenStore(t, home)
	if ev, _, _ := s.Get("inv:0000000000050:aa"); ev.SyncStatus != 0 {
		t.Fatalf("divergent row must stay unsynced: %+v", ev)
	}
}
