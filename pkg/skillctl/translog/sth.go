package translog

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// STHDomain is the domain separator for a Signed Tree Head signature. It is
// DISTINCT from every other signed-message family in the spine
// ("attestation" in signing/attest.go, "revoke" in signing/revoke.go, the
// AgentID envelopes, the device-token envelope, ...). Because the domain
// string is the FIRST line of the signed message, an ed25519 signature
// produced over an STH can never be byte-equal to — and therefore never be
// replayed as — an attestation, a revocation, or any other envelope; and
// vice versa. Bumping the "-v1" suffix is how we'd migrate the STH format
// without a cross-family collision.
const STHDomain = "skillctl-sth-v1"

// STHTimestampLayout is the exact wire format for the STH timestamp: RFC
// 3339, UTC, second precision, "Z" suffix. No fractional seconds and no
// numeric offset, so the signed bytes are deterministic across platforms
// (mirrors signing.AttestationTimestampLayout).
const STHTimestampLayout = "2006-01-02T15:04:05Z"

// sthTimestampPattern is the strict acceptance pattern for the timestamp
// line: it must match the layout above exactly.
var sthTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// logIDPattern restricts a log id to a small safe character set so it can
// never inject a newline into the canonical message (which would let an
// attacker shift field boundaries).
var logIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// STH errors.
var (
	// ErrSTHMalformed — the STH failed structural validation before any
	// crypto check (bad size, bad timestamp, empty root, bad log id).
	ErrSTHMalformed = errors.New("translog: malformed signed tree head")
	// ErrSTHSignatureInvalid — the ed25519 signature did not verify
	// against the pinned log key. Covers BOTH a forged signature and an
	// STH signed by a NON-pinned key (the caller passes the pinned key;
	// any other signer fails here).
	ErrSTHSignatureInvalid = errors.New("translog: STH signature invalid (wrong or unpinned log key)")
)

// STH is a Signed Tree Head: a log operator's signed commitment to "at
// this timestamp, my log had exactly TreeSize entries and this RootHash."
// It is the anchor a verifier pins (with the log's public key) and checks
// inclusion proofs against — entirely offline.
//
// Per SPEC-0278 §3.4 the trust-roots file pins the log public key plus a
// recent STH (or a witnessed-STH set); this struct is that pinned object.
type STH struct {
	// TreeSize is the number of leaves committed. Must be >= 1 — we never
	// sign over an empty tree.
	TreeSize int `json:"tree_size" yaml:"tree_size"`

	// RootHash is the RFC-6962 Merkle Tree Hash over the TreeSize leaves,
	// hex-encoded (64 lowercase hex chars).
	RootHash string `json:"root_hash" yaml:"root_hash"`

	// Timestamp is when the operator signed this head, in STHTimestampLayout.
	Timestamp string `json:"timestamp" yaml:"timestamp"`

	// LogID identifies WHICH log this head belongs to. Cross-witness
	// split-view detection only compares STHs carrying the SAME LogID (two
	// heads of two different logs at the same size are not a conflict).
	LogID string `json:"log_id" yaml:"log_id"`

	// Signature is the ed25519 signature over CanonicalSTHMessage, hex-
	// encoded (128 lowercase hex chars). Empty on an unsigned STH.
	Signature string `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// RootBytes decodes RootHash into a fixed [HashSize]byte. Returns
// ErrSTHMalformed if the hex is the wrong length or not valid hex — so a
// caller can never hand a half-decoded root into VerifyInclusion.
func (s STH) RootBytes() ([HashSize]byte, error) {
	var out [HashSize]byte
	raw, err := hex.DecodeString(s.RootHash)
	if err != nil {
		return out, fmt.Errorf("%w: root_hash not hex: %v", ErrSTHMalformed, err)
	}
	if len(raw) != HashSize {
		return out, fmt.Errorf("%w: root_hash is %d bytes, want %d", ErrSTHMalformed, len(raw), HashSize)
	}
	copy(out[:], raw)
	return out, nil
}

// validateShape runs the non-crypto structural checks shared by signing and
// verification. Doing them BEFORE assembling the canonical message means we
// never sign over malformed bytes and never attempt a verify against a
// nonsense head.
func (s STH) validateShape() error {
	if s.TreeSize < 1 {
		return fmt.Errorf("%w: tree_size must be >= 1, got %d", ErrSTHMalformed, s.TreeSize)
	}
	if len(s.RootHash) != HashSize*2 {
		return fmt.Errorf("%w: root_hash must be %d hex chars, got %d", ErrSTHMalformed, HashSize*2, len(s.RootHash))
	}
	if _, err := s.RootBytes(); err != nil {
		return err
	}
	if !sthTimestampPattern.MatchString(s.Timestamp) {
		return fmt.Errorf("%w: timestamp %q is not RFC3339 UTC seconds", ErrSTHMalformed, s.Timestamp)
	}
	if !logIDPattern.MatchString(s.LogID) {
		return fmt.Errorf("%w: log_id %q invalid (allowed: [A-Za-z0-9._:-], 1-128 chars)", ErrSTHMalformed, s.LogID)
	}
	return nil
}

// CanonicalSTHMessage returns the exact bytes signed/verified for this STH.
// Format (UTF-8, LF-separated, trailing LF):
//
//	skillctl-sth-v1\n
//	<tree_size>\n          decimal, no leading zeros
//	<root_hash>\n          64 lowercase hex
//	<timestamp>\n          RFC3339 UTC seconds
//	<log_id>\n
//
// The leading domain line is what isolates STH signatures from every other
// envelope family. Strict shape validation runs first.
func (s STH) CanonicalSTHMessage() ([]byte, error) {
	if err := s.validateShape(); err != nil {
		return nil, err
	}
	// Re-encode tree_size from the int so the bytes are canonical (no
	// stray leading zeros could ever be smuggled in via a struct field).
	var b strings.Builder
	b.WriteString(STHDomain)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(s.TreeSize))
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(s.RootHash))
	b.WriteByte('\n')
	b.WriteString(s.Timestamp)
	b.WriteByte('\n')
	b.WriteString(s.LogID)
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// SignSTH signs an STH with the log's ed25519 private key and returns a
// copy with Signature populated (hex). The input's Signature field is
// ignored. logKey must be the LOG signing key — distinct from author /
// registry / attestation keys.
func SignSTH(logKey ed25519.PrivateKey, s STH) (STH, error) {
	if len(logKey) != ed25519.PrivateKeySize {
		return STH{}, fmt.Errorf("%w: log private key is %d bytes, want %d", ErrSTHMalformed, len(logKey), ed25519.PrivateKeySize)
	}
	msg, err := s.CanonicalSTHMessage()
	if err != nil {
		return STH{}, err
	}
	sig := ed25519.Sign(logKey, msg)
	out := s
	out.Signature = hex.EncodeToString(sig)
	return out, nil
}

// VerifySTH checks the STH signature against the PINNED log public key.
//
// This is the single chokepoint for "is this STH authentic and from the
// log I trust." An STH signed by ANY key other than logPub fails with
// ErrSTHSignatureInvalid — so a head signed by an unpinned key is refused,
// and a forged head whose root does not match its signed bytes is refused.
// (Whether the root actually matches a set of leaves is a separate concern,
// checked by VerifyInclusion / the log builder.)
func VerifySTH(logPub ed25519.PublicKey, s STH) error {
	if len(logPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: log public key is %d bytes, want %d", ErrSTHMalformed, len(logPub), ed25519.PublicKeySize)
	}
	msg, err := s.CanonicalSTHMessage()
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature not hex: %v", ErrSTHMalformed, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrSTHMalformed, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(logPub, msg, sig) {
		return ErrSTHSignatureInvalid
	}
	return nil
}

// Equal reports whether two STHs commit to the same (tree_size, root_hash,
// log_id). Timestamp and signature are intentionally excluded: two honest
// re-signings of the same head at different times are NOT a conflict, but
// the same size with a DIFFERENT root IS (see VerifyWitnessConsistency).
func (s STH) Equal(o STH) bool {
	return s.TreeSize == o.TreeSize &&
		s.LogID == o.LogID &&
		subtle.ConstantTimeCompare([]byte(strings.ToLower(s.RootHash)), []byte(strings.ToLower(o.RootHash))) == 1
}

// FormatSTHTimestamp renders t as the canonical STH timestamp string.
func FormatSTHTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(STHTimestampLayout)
}
