package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func mkDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// TestRevocationHeadGoldenVector pins the EXACT canonical bytes a cross-language
// producer (the aims-core Python HEAD endpoint, FR-0045 D2) must reproduce so its
// ed25519 signature verifies here. A one-character divergence in either encoder
// breaks it. The Python test asserts json.dumps(head, separators=(",",":"),
// sort_keys=True, ensure_ascii=False) == this same string.
// TestRevokedSetRootGolden pins the ComputeRevokedSetRoot output for a fixed
// 2-digest set so the aims-core Python compute_revoked_set_root can be asserted
// against the identical hex (cross-language set-root agreement).
func TestRevokedSetRootGolden(t *testing.T) {
	got := ComputeRevokedSetRoot([]string{mkDigest('b'), mkDigest('a')})
	const golden = "sha256:4ab61be5d46a66e7f659b66144d4bead5b761c247b565fa202161590dcd9e45d"
	if got != golden {
		t.Fatalf("set-root golden mismatch:\n got: %s\nwant: %s", got, golden)
	}
}

func TestRevocationHeadGoldenVector(t *testing.T) {
	fixed := map[string]any{
		"schema_version":   RevocationHeadSchema,
		"event_id":         "fixed-event-id-0001",
		"occurred_at":      "2026-07-06T18:00:00Z",
		"epoch":            42,
		"issued_at":        "2026-07-06T18:00:00Z",
		"revoked_set_root": "sha256:" + strings.Repeat("a", 64),
		"revoked_count":    2,
		"emergency":        []any{"sha256:" + strings.Repeat("b", 64)},
		"tenant_scope":     nil,
	}
	got, err := CanonicalEventBytes(fixed)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	const golden = `{"emergency":["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"epoch":42,"event_id":"fixed-event-id-0001","issued_at":"2026-07-06T18:00:00Z","occurred_at":"2026-07-06T18:00:00Z","revoked_count":2,"revoked_set_root":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"m3c-revocation-head/v1","tenant_scope":null}`
	if string(got) != golden {
		t.Fatalf("golden vector mismatch — cross-language canonicalization would break.\n got: %s\nwant: %s", got, golden)
	}
}

func mustHead(t *testing.T, in RevocationHeadInput) map[string]any {
	t.Helper()
	h, err := BuildRevocationHead(in)
	if err != nil {
		t.Fatalf("BuildRevocationHead: %v", err)
	}
	return h
}

func TestBuildRevocationHead_HappyPath(t *testing.T) {
	ts := time.Date(2026, 7, 6, 18, 0, 0, 0, time.UTC)
	h := mustHead(t, RevocationHeadInput{
		Epoch:     42,
		IssuedAt:  ts,
		Digests:   []string{mkDigest('b'), mkDigest('a')},
		Emergency: []string{mkDigest('a')},
	})
	if h["schema_version"] != RevocationHeadSchema {
		t.Errorf("schema_version = %v", h["schema_version"])
	}
	if h["issued_at"] != "2026-07-06T18:00:00Z" {
		t.Errorf("issued_at = %v", h["issued_at"])
	}
	if got, _ := HeadEpoch(h); got != 42 {
		t.Errorf("epoch = %d, want 42", got)
	}
	if h["revoked_count"].(int) != 2 {
		t.Errorf("revoked_count = %v, want 2", h["revoked_count"])
	}
	// revoked_set_root binds to the set regardless of input order.
	if h["revoked_set_root"] != ComputeRevokedSetRoot([]string{mkDigest('a'), mkDigest('b')}) {
		t.Errorf("revoked_set_root not order-independent")
	}
}

func TestBuildRevocationHead_Validation(t *testing.T) {
	cases := []struct {
		name string
		in   RevocationHeadInput
	}{
		{"negative epoch", RevocationHeadInput{Epoch: -1}},
		{"bad revoked digest", RevocationHeadInput{Epoch: 1, Digests: []string{"not-a-digest"}}},
		{"bad emergency digest", RevocationHeadInput{Epoch: 1, Digests: []string{mkDigest('a')}, Emergency: []string{"nope"}}},
		{"emergency not subset", RevocationHeadInput{Epoch: 1, Digests: []string{mkDigest('a')}, Emergency: []string{mkDigest('c')}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildRevocationHead(tc.in); !errors.Is(err, ErrInvalidHead) {
				t.Errorf("want ErrInvalidHead, got %v", err)
			}
		})
	}
}

func TestComputeRevokedSetRoot_Deterministic(t *testing.T) {
	a, b, c := mkDigest('a'), mkDigest('b'), mkDigest('c')
	root := ComputeRevokedSetRoot([]string{a, b, c})
	// order-independent
	if ComputeRevokedSetRoot([]string{c, b, a}) != root {
		t.Errorf("root depends on order")
	}
	// dedup-independent
	if ComputeRevokedSetRoot([]string{a, a, b, c, c}) != root {
		t.Errorf("root depends on duplicates")
	}
	// distinct sets differ
	if ComputeRevokedSetRoot([]string{a, b}) == root {
		t.Errorf("distinct sets share a root")
	}
	// empty set has a stable non-empty root string
	if e := ComputeRevokedSetRoot(nil); !strings.HasPrefix(e, "sha256:") || len(e) != len("sha256:")+64 {
		t.Errorf("empty-set root malformed: %q", e)
	}
}

func TestRevocationHead_SignVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := mustHead(t, RevocationHeadInput{
		Epoch:    7,
		IssuedAt: time.Now().UTC(),
		Digests:  []string{mkDigest('a'), mkDigest('b')},
	})
	if _, err := SignEnvelopeSignature(priv, h); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyEnvelopeSignature(pub, h); err != nil {
		t.Fatalf("verify in-process: %v", err)
	}

	// The decisive test: after JSON transport (epoch int -> float64), the
	// signature must still verify and epoch must read back as the same int.
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyEnvelopeSignature(pub, decoded); err != nil {
		t.Fatalf("verify after JSON round-trip: %v", err)
	}
	if got, _ := HeadEpoch(decoded); got != 7 {
		t.Errorf("epoch after round-trip = %d, want 7", got)
	}
}

func TestRevocationHead_TamperDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := mustHead(t, RevocationHeadInput{Epoch: 3, IssuedAt: time.Now().UTC(), Digests: []string{mkDigest('a')}})
	if _, err := SignEnvelopeSignature(priv, h); err != nil {
		t.Fatalf("sign: %v", err)
	}
	h["epoch"] = 4 // attacker bumps the epoch after signing
	if err := VerifyEnvelopeSignature(pub, h); !errors.Is(err, ErrEnvelopeSignatureInvalid) {
		t.Errorf("tampered epoch not detected: %v", err)
	}
}

func TestVerifyRevocationHeadSet(t *testing.T) {
	digests := []string{mkDigest('a'), mkDigest('b'), mkDigest('c')}
	h := mustHead(t, RevocationHeadInput{Epoch: 1, IssuedAt: time.Now().UTC(), Digests: digests})

	if err := VerifyRevocationHeadSet(h, []string{mkDigest('c'), mkDigest('a'), mkDigest('b')}); err != nil {
		t.Errorf("matching set (reordered) rejected: %v", err)
	}
	// truncated set (attacker drops a revocation)
	if err := VerifyRevocationHeadSet(h, []string{mkDigest('a'), mkDigest('b')}); !errors.Is(err, ErrHeadSetRootMismatch) {
		t.Errorf("truncated set not detected: %v", err)
	}
	// swapped-in bogus digest
	if err := VerifyRevocationHeadSet(h, []string{mkDigest('a'), mkDigest('b'), mkDigest('d')}); !errors.Is(err, ErrHeadSetRootMismatch) {
		t.Errorf("forged set not detected: %v", err)
	}
}

func TestCheckEpochMonotonic(t *testing.T) {
	h := mustHead(t, RevocationHeadInput{Epoch: 10, IssuedAt: time.Now().UTC()})
	if err := CheckEpochMonotonic(h, 10); err != nil {
		t.Errorf("equal epoch rejected: %v", err)
	}
	if err := CheckEpochMonotonic(h, 5); err != nil {
		t.Errorf("higher epoch rejected: %v", err)
	}
	if err := CheckEpochMonotonic(h, 11); !errors.Is(err, ErrHeadRollback) {
		t.Errorf("rollback not detected: %v", err)
	}
}

func TestAdoptRevocationHead(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	set := []string{mkDigest('a'), mkDigest('b')}
	ts := time.Date(2026, 7, 6, 18, 0, 0, 0, time.UTC)

	newSignedHead := func(epoch int) map[string]any {
		h := mustHead(t, RevocationHeadInput{Epoch: epoch, IssuedAt: ts, Digests: set})
		if _, err := SignEnvelopeSignature(priv, h); err != nil {
			t.Fatalf("sign: %v", err)
		}
		return h
	}

	t.Run("happy", func(t *testing.T) {
		ep, iss, err := AdoptRevocationHead(pub, newSignedHead(5), set, 5)
		if err != nil || ep != 5 || !iss.Equal(ts) {
			t.Fatalf("adopt = %d,%v,%v", ep, iss, err)
		}
	})
	t.Run("bad signature (wrong key) -> reject", func(t *testing.T) {
		if _, _, err := AdoptRevocationHead(otherPub, newSignedHead(5), set, 0); !errors.Is(err, ErrEnvelopeSignatureInvalid) {
			t.Errorf("want ErrEnvelopeSignatureInvalid, got %v", err)
		}
	})
	t.Run("rollback -> reject", func(t *testing.T) {
		if _, _, err := AdoptRevocationHead(pub, newSignedHead(4), set, 9); !errors.Is(err, ErrHeadRollback) {
			t.Errorf("want ErrHeadRollback, got %v", err)
		}
	})
	t.Run("set mismatch -> reject", func(t *testing.T) {
		if _, _, err := AdoptRevocationHead(pub, newSignedHead(5), []string{mkDigest('a')}, 0); !errors.Is(err, ErrHeadSetRootMismatch) {
			t.Errorf("want ErrHeadSetRootMismatch, got %v", err)
		}
	})
}

func TestHeadAccessors_FromDecodedMap(t *testing.T) {
	ts := time.Date(2026, 7, 6, 12, 30, 0, 0, time.UTC)
	h := mustHead(t, RevocationHeadInput{
		Epoch:     99,
		IssuedAt:  ts,
		Digests:   []string{mkDigest('a'), mkDigest('b')},
		Emergency: []string{mkDigest('a')},
	})
	raw, _ := json.Marshal(h)
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, err := HeadEpoch(decoded); err != nil || got != 99 {
		t.Errorf("HeadEpoch = %d, %v", got, err)
	}
	if got, err := HeadIssuedAt(decoded); err != nil || !got.Equal(ts) {
		t.Errorf("HeadIssuedAt = %v, %v", got, err)
	}
	em, err := HeadEmergency(decoded)
	if err != nil || len(em) != 1 || em[0] != mkDigest('a') {
		t.Errorf("HeadEmergency = %v, %v", em, err)
	}
}
