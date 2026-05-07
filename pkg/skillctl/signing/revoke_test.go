package signing

import (
	"crypto/ed25519"
	"testing"
)

// Cross-language test vector. The Python counterpart in
// aims-core/.../tests/test_revoke.py::TestCanonicalMessage::test_canonical_bytes_match_spec
// pins the SAME bytes via canonicalize_revocation_message(). Any drift
// here breaks the trust chain silently.
const (
	revokeTestVectorDigest    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revokeTestVectorTimestamp = "2026-05-06T15:00:00Z"
	revokeTestVectorRole      = "original_author"
)

var revokeTestVectorExpected = []byte("revoke\n" +
	"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
	"2026-05-06T15:00:00Z\n" +
	"original_author\n")

func TestCanonicalizeRevocationMessage_TestVector(t *testing.T) {
	got, err := CanonicalizeRevocationMessage(
		revokeTestVectorDigest,
		revokeTestVectorTimestamp,
		revokeTestVectorRole,
	)
	if err != nil {
		t.Fatalf("CanonicalizeRevocationMessage: %v", err)
	}
	if string(got) != string(revokeTestVectorExpected) {
		t.Errorf("byte mismatch:\n got: %q\nwant: %q", got, revokeTestVectorExpected)
	}
}

func TestCanonicalizeRevocationMessage_AllThreeRoles(t *testing.T) {
	for _, role := range []string{"registry_operator", "governance_reviewer", "original_author"} {
		t.Run(role, func(t *testing.T) {
			got, err := CanonicalizeRevocationMessage(
				revokeTestVectorDigest, revokeTestVectorTimestamp, role,
			)
			if err != nil {
				t.Fatalf("role=%q: %v", role, err)
			}
			expected := []byte("revoke\n" + revokeTestVectorDigest + "\n" + revokeTestVectorTimestamp + "\n" + role + "\n")
			if string(got) != string(expected) {
				t.Errorf("role=%q byte mismatch:\n got: %q\nwant: %q", role, got, expected)
			}
		})
	}
}

func TestCanonicalizeRevocationMessage_RejectsBadDigest(t *testing.T) {
	for _, d := range []string{"", "not-a-digest", "sha256:" + "ZZ", "sha256:" + "aa"} {
		t.Run(d, func(t *testing.T) {
			if _, err := CanonicalizeRevocationMessage(d, revokeTestVectorTimestamp, revokeTestVectorRole); err == nil {
				t.Errorf("expected error for digest %q", d)
			}
		})
	}
}

func TestCanonicalizeRevocationMessage_RejectsBadRole(t *testing.T) {
	for _, role := range []string{"", "rogue_admin", "Author", "ORIGINAL_AUTHOR"} {
		t.Run(role, func(t *testing.T) {
			if _, err := CanonicalizeRevocationMessage(revokeTestVectorDigest, revokeTestVectorTimestamp, role); err == nil {
				t.Errorf("expected error for role %q", role)
			}
		})
	}
}

func TestCanonicalizeRevocationMessage_RejectsBadTimestamp(t *testing.T) {
	for _, ts := range []string{"", "2026-05-06T15:00:00", "2026-05-06 15:00:00Z", "2026-05-06T15:00:00.123Z"} {
		t.Run(ts, func(t *testing.T) {
			if _, err := CanonicalizeRevocationMessage(revokeTestVectorDigest, ts, revokeTestVectorRole); err == nil {
				t.Errorf("expected error for timestamp %q", ts)
			}
		})
	}
}

func TestSignRevocation_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg, err := CanonicalizeRevocationMessage(
		revokeTestVectorDigest, revokeTestVectorTimestamp, revokeTestVectorRole,
	)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := SignRevocation(priv, msg)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Errorf("signature did not verify against the message")
	}
}
