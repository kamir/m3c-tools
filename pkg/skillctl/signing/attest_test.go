package signing

// Stream S9-cli (SPEC-0188 Phase 5). Tests for the attestation
// canonicalize + sign primitives.
//
// The cross-language byte-equality test (TestCanonicalizeAttestationMessage_TestVector)
// is the single most important assertion in this file: if it fails, the
// Python S9-aims serializer and the Go S9-cli serializer have drifted and
// every signature produced by the CLI will be rejected by the registry.

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The cross-language test vector from the S9 brief. Both Python and Go
// MUST produce these exact bytes for the listed inputs. Hardcoded here so
// any drift trips the test in CI before it can reach the wire.
const (
	testVectorDigest      = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	testVectorLevel       = "green"
	testVectorAttestedAt  = "2026-05-05T19:30:00Z"
	testVectorReviewerID  = "id:test@s9"
	testVectorWireMessage = "attestation\n" +
		"sha256:0000000000000000000000000000000000000000000000000000000000000001\n" +
		"green\n" +
		"2026-05-05T19:30:00Z\n" +
		"id:test@s9\n"
)

func TestCanonicalizeAttestationMessage_TestVector(t *testing.T) {
	got, err := CanonicalizeAttestationMessage(
		testVectorDigest,
		testVectorLevel,
		testVectorAttestedAt,
		testVectorReviewerID,
	)
	if err != nil {
		t.Fatalf("CanonicalizeAttestationMessage on test vector: %v", err)
	}
	want := []byte(testVectorWireMessage)
	if string(got) != string(want) {
		t.Fatalf("canonical bytes differ from cross-language test vector\n  got  = %q (%d bytes)\n  want = %q (%d bytes)", got, len(got), want, len(want))
	}
	// Sanity: final byte must be \n; no \r anywhere.
	if got[len(got)-1] != '\n' {
		t.Errorf("final byte is %q, want '\\n'", got[len(got)-1])
	}
	for i, b := range got {
		if b == '\r' {
			t.Errorf("CR byte at offset %d; canonical bytes must use LF only", i)
		}
	}
}

func TestCanonicalizeAttestationMessage_TestVectorByteCount(t *testing.T) {
	// Document the actual byte count of the test vector message.
	// 12 (attestation\n) + 72 (sha256:<64hex>\n) + 6 (green\n)
	// + 21 (2026-05-05T19:30:00Z\n) + 11 (id:test@s9\n) = 122.
	const expected = 122
	got, err := CanonicalizeAttestationMessage(
		testVectorDigest,
		testVectorLevel,
		testVectorAttestedAt,
		testVectorReviewerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != expected {
		t.Fatalf("test vector message length = %d, want %d", len(got), expected)
	}
}

func TestCanonicalizeAttestationMessage_RejectsBadDigest(t *testing.T) {
	cases := []struct {
		name   string
		digest string
	}{
		{"missing prefix", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"wrong prefix", "sha512:" + strings.Repeat("0", 64)},
		{"too short", "sha256:" + strings.Repeat("0", 63)},
		{"too long", "sha256:" + strings.Repeat("0", 65)},
		{"uppercase hex", "sha256:" + strings.Repeat("A", 64)},
		{"non-hex chars", "sha256:" + strings.Repeat("g", 64)},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CanonicalizeAttestationMessage(tc.digest, "green", testVectorAttestedAt, testVectorReviewerID); err == nil {
				t.Fatalf("accepted bad digest %q", tc.digest)
			}
		})
	}
}

func TestCanonicalizeAttestationMessage_RejectsBadLevel(t *testing.T) {
	cases := []string{"", "blue", "GREEN", "Green", " green", "green ", "yel", "0"}
	for _, level := range cases {
		level := level
		t.Run("level="+level, func(t *testing.T) {
			if _, err := CanonicalizeAttestationMessage(testVectorDigest, level, testVectorAttestedAt, testVectorReviewerID); err == nil {
				t.Fatalf("accepted bad level %q", level)
			}
		})
	}
}

func TestCanonicalizeAttestationMessage_RejectsBadTimestamp(t *testing.T) {
	cases := []struct {
		name string
		ts   string
	}{
		{"empty", ""},
		{"missing Z", "2026-05-05T19:30:00"},
		{"with offset", "2026-05-05T19:30:00+00:00"},
		{"with fractional seconds", "2026-05-05T19:30:00.123Z"},
		{"date only", "2026-05-05"},
		{"local format", "2026-05-05 19:30:00"},
		{"non-rfc3339", "Tue, 05 May 2026 19:30:00 UTC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CanonicalizeAttestationMessage(testVectorDigest, "green", tc.ts, testVectorReviewerID); err == nil {
				t.Fatalf("accepted bad timestamp %q", tc.ts)
			}
		})
	}
}

func TestCanonicalizeAttestationMessage_RejectsBadReviewerID(t *testing.T) {
	cases := []struct {
		name string
		rid  string
	}{
		{"empty", ""},
		{"contains LF", "id:foo@bar\nextra"},
		{"trailing LF", "id:foo@bar\n"},
		{"contains CR", "id:foo\rbar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CanonicalizeAttestationMessage(testVectorDigest, "green", testVectorAttestedAt, tc.rid); err == nil {
				t.Fatalf("accepted bad reviewer_id %q", tc.rid)
			}
		})
	}
}

func TestFormatAttestationTimestamp_AlwaysUTCSeconds(t *testing.T) {
	// A non-UTC timestamp with sub-second precision must come out as
	// the canonical form: UTC, second precision, Z suffix.
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("time zone db unavailable: %v", err)
	}
	t0 := time.Date(2026, 5, 5, 15, 30, 0, 123456789, loc) // 19:30:00 UTC
	got := FormatAttestationTimestamp(t0)
	want := "2026-05-05T19:30:00Z"
	if got != want {
		t.Errorf("FormatAttestationTimestamp = %q, want %q", got, want)
	}
}

func TestFormatAttestationTimestamp_TruncatesFractional(t *testing.T) {
	t0 := time.Date(2026, 5, 5, 19, 30, 0, 999999999, time.UTC)
	got := FormatAttestationTimestamp(t0)
	if got != "2026-05-05T19:30:00Z" {
		t.Errorf("fractional seconds leaked: %q", got)
	}
}

func TestSignAttestation_RoundTripsAgainstStdlib(t *testing.T) {
	// Generate a keypair via Generate (writes to disk), load it,
	// sign the canonical test-vector message, verify it with stdlib.
	dir := t.TempDir()
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(keyOut + ".priv")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(keyOut + ".pub")
	if err != nil {
		t.Fatal(err)
	}

	msg, err := CanonicalizeAttestationMessage(
		testVectorDigest, testVectorLevel, testVectorAttestedAt, testVectorReviewerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	sig := SignAttestation(priv, msg)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519.Verify rejected our own signature")
	}

	// Tamper one byte → verify must reject.
	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[len(tampered)/2] ^= 0xFF
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("verify accepted tampered message")
	}
}

func TestSignAttestation_DeterministicForSameInputs(t *testing.T) {
	// ed25519 is deterministic — same key + same message → same signature.
	// This guards against accidentally introducing nonces or other
	// non-determinism in our wrapper.
	dir := t.TempDir()
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(keyOut + ".priv")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("attestation\nsha256:" + strings.Repeat("0", 63) + "1\ngreen\n2026-05-05T19:30:00Z\nid:x@y\n")
	sig1 := SignAttestation(priv, msg)
	sig2 := SignAttestation(priv, msg)
	if string(sig1) != string(sig2) {
		t.Fatal("ed25519 wrapper produced non-deterministic signatures")
	}
}
